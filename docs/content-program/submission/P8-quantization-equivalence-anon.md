# One Ladder, Opposite Directions

### Directional churn in quantized guard classifiers, and what a paired equivalence standard costs when applied to them

**Anonymous submission — under double-blind review**

> **Anonymization note.** Author, affiliation and the identity of companion submissions are
> withheld for double-blind review. Citations of the form `[Anon-*]` are unpublished companion
> work by the same authors and are anonymized accordingly; **all third-party citations are
> intact**. Pre-registration hashes are retained deliberately: they are this paper's evidence
> of pre-registration, and a SHA-256 identifies a frozen document rather than a person.
*Draft 2 follows a complete read of [Certify]. Three claims corrected, all against us, and one result added that Draft 1 could not have found. Corrections are marked in place.*

---

> ⚠️ **The instrument is not ours, and neither is the cross-scheme audit.** A literature check run
> **before the design** — not before the draft — found two 2026 papers that between them own most of
> what we had planned:
>
> - **[Certify]** (Singh, arXiv:2608.15046) supplies the paired-equivalence method used throughout
>   §5.4: TOST at a declared margin, sized from **observed discordance** rather than
>   independent-binomial variance. Their atlas of **1,707 paired cells** establishes that per-item
>   churn runs **roughly five times the net accuracy delta**, and that cells scoring identically to
>   their baseline still disagree item by item.
> - **[QualityProxy]** (Kadadekar, arXiv:2606.10154) supplies the cross-scheme safety audit: a 51-row
>   matched matrix over a GGUF ladder plus **AWQ INT4 and GPTQ INT4**.
>
> **We cut our planned scheme extension entirely, and not for cost.** [Certify] show the
> GPTQ-versus-AWQ ordering **reverses with the calibration draw alone**, in 5 of 8 confirmatory cells.
> Running that comparison without controlling the calibration draw would have produced an artifact.
> **Declining to run it is what the check bought.**
>
> **What remains is the object neither paper measures.** [QualityProxy] measures a generative model's
> refusal behavior through an LLM judge; [Certify]'s atlas is benchmark accuracy. **Neither measures a
> dedicated guard classifier**, whose verdict *is* the measurement rather than something a judge
> infers from a generation — and whose two error directions are not interchangeable, which is where
> this paper's contribution lives.
>
> ⚠️ **Draft 1 was written on a partial read of [Certify] and was wrong three times.** Finishing
> §3.5–§3.8, §4 and §9 corrected: the ratio we compared against (§5.1), the fact that we reported
> required sample sizes **without ever running the test they size** (§5.4), and the population we may
> extrapolate from (§7). **Every correction ran against us.** It also produced §5.5, the strongest
> result in the paper, which a partial read could not have reached.

---

## Abstract

Guard models are deployed quantized. Whether that changes their verdicts is usually settled with a
net rate delta, and concurrent work shows why that is the weakest available evidence: a net delta is
the residue after opposing per-item changes cancel, and cancellation is most complete exactly where
equivalence claims are made [Certify].

We apply their paired-equivalence instrument to five guard classifiers from three publishers across a
seven-level GGUF ladder — 35 cells, 1,000 shared items, per-item verdicts, each compared against that
model's own `F16` reference.

**Five results.**

**First, their headline ratio does not transfer, though smaller than Draft 1 claimed.** Computed as
they compute it — the median of finite cellwise ratios — guard verdict churn runs **1.86× the net
accuracy delta** against their **3.85×**. ⚠️ Draft 1 reported 1.4× against their 5.40×, comparing a
cellwise median to a ratio-of-medians and partitioning by verdict direction rather than by
correctness. **Both figures are now computed both ways against their matching statistic** (ratio of
medians: ours 2.75×, theirs 5.40×).

**Second, and this is the strongest result here: the evidential crisis their paper documents does not
occur in this domain.** They report the share of cells that are neither certifiable at the registered
±2pp margin nor detectably different — the gray zone where an evaluation cannot answer the question a
release note answers — at **69.2%** of their 1,398-cell first stratum and **77.7%** of the second.
**For the guard ladder it is 0.0%.** Every one of 30 cells is either provably equivalent at ±2pp
(70.0%) or detectably different (30.0%). Guard verdicts churn little enough that 1,000 items settles
the question, where a general-model benchmark of the same size cannot.

**Third, and this is what a symmetric accuracy metric structurally cannot see: quantization has a
safety direction, and the model picks it, not the bit-width.** On the same ladder, ShieldGemma 9B
loses almost only unsafe detections (**144 unsafe→safe against 4 the other way, 0.97**) while
Qwen3Guard 4B almost only over-blocks (**0.33**). ShieldGemma 2B **reverses mid-ladder**: purely
usability-adverse at `Q4_K_M` and `Q3_K_M` (0 unsafe→safe in both), then **47-to-1 safety-adverse at
`Q2_K`**. A deployer cannot infer which way a guard will fail from the precision it is served at.

**Fourth, applying [Certify]'s certification sizing to guards reproduces their central conceptual
point in a new domain: the requirement tracks churn, not quality.** The worst guard we measure (FNR
0.857) and a mid-range one (FNR 0.280) require **identical** evidence — 1,113 items at a ±1
percentage-point margin — while the best (FNR 0.028) needs 248. **Three of five models need more items
than the 1,000 this evaluation ran**, so a benchmark of this size cannot certify them at ±1pp.

**Fifth, the mechanism for that direction exists in the literature, it is not ours, and we tested
whether it reaches guards at all.** [MarginShrink] fit a proportional damage law, *m'* = *c·m* + *b* + ε,
on 16 generative instruct models; **no guard classifier appears in their study, nor in [Certify] or
[QualityProxy]**. We captured decision margins for two guards across seven precisions and find the law
**transfers**: the multiplicative form beats a constant-additive one in 5 of 6 cells in both models,
and their flip predictor — fitted on margins, never on flips — predicts guard flip rates to **0.75 and
0.94 percentage points** against their 1.7pp median. The fitted push *b* **disagrees in sign between
the two guards and reverses within a single ladder**, which is the shape of the behavior in the third
result. ⚠️ **This test required a different serving stack**, because the GGUF stack cannot expose
logits at all, so it establishes the law for guards as a class rather than for the cells above. **Its
pre-registered monotonicity check failed and is reported as failed.**

We also report a concern of our own that did not survive testing. Companion work recorded
that the serving-noise floor is not a single number: on verdict-selected sets it ran 1.0–5.7%, which
would have left **27 of 30 cells** indistinguishable from noise. Rather than argue which floor
applies, we measured it on this corpus with eight same-configuration replicates, deliberately choosing
the model whose churn most favored the null. **The floor is 0.107% — two unstable items in a thousand
— the stratified figure, not the borderline one. The concern was wrong.**

**Keywords:** guard models, quantization, model compression, equivalence testing, safety evaluation,
measurement study

---

## 1. What this paper is

**The method is [Certify]'s and we apply it.** Their five-line reporting standard is explicitly
general — *"It applies to any comparison between two models alike enough to be worth comparing"* — and
this is an application of it, not a competitor to it.

**A borrowed instrument is not a borrowed result.** We say this once, plainly, because the
alternative reading would misplace the paper. [Certify]'s atlas is benchmark accuracy and
[QualityProxy]'s outcome is a generative model's refusal scored by an LLM judge. **Neither measures a
guard classifier** — the component that actually sits in the request path and whose verdict *is* the
decision rather than something a judge infers from a generation. Applying their instrument there
produces findings neither could have observed, and two of the three below are work the sources
**named as outstanding and did not do**.

**Three things remain, and we claim only these:**

1. **Directional churn** (§5.2). [Certify]'s churn is symmetric by construction, because
   correct→wrong and wrong→correct are the same kind of event on a benchmark. **On a guard they are
   not**: `unsafe→safe` admits harmful content, `safe→unsafe` only over-blocks. This decomposition is
   unavailable in their setting, and it turns out to carry the paper's most actionable finding.
2. **A measured floor for the corpus the claims are made on** (§5.6). [Certify] size their tests from
   disagreement observed *under compression*. We add an independently measured
   *same-configuration* floor, which is a different quantity and which their toolkit does not carry.
3. **Two extensions the prior art explicitly asks for.** [QualityProxy] §5.3 names its own equivalence
   gap — *it does not run a formal two-one-sided-tests procedure for every cell*, and directs readers
   needing a certified statement to *"apply a targeted TOST to the specific metric, model, and
   quantization cell of interest."* **§5.5 does that for all 30 cells.** [Certify] §3.6 requires that
   the test they size actually be run; **§5.5 runs it.** Neither is a novel instrument; both are work
   the sources named as outstanding.

4. **A test of whether the known mechanism reaches this object** (§5.8). [MarginShrink]'s damage law
   is fitted entirely on generative instruct models. **Whether it governs a classifier whose verdict
   *is* the decision was untested by them or by anyone**, and an earlier draft of this paper listed it
   as a gap we could not close. We closed it. **The law is theirs; the measurement of its reach, and
   one negative result inside it, are ours.**

**We claim no novelty on:** the churn-versus-net-delta argument, the cancellation account, TOST
certification sizing, the observation that aggregate scores conceal per-item movement, or the
cross-scheme safety audit. **All are prior art**, cited at first use.

⚠️ **Our first hypothesis was not blind.** The M3 and M3-X per-item verdicts existed on disk before
this study was designed, and their headline — 4 to 18 verdicts per thousand differing at `Q4_K_M` —
was known. §5.1 is confirmatory of an expectation already formed. §5.2 and §5.4 were not.

## 2. Related work

**[Certify]** audits 17 published equivalence claims from three registered sampling frames and finds
none declares a prospective numerical margin and none releases task-matched per-item outputs. Its
atlas puts churn at ~5× the net delta across 1,707 cells spanning 1.3B to 405B parameters. Its
controlled experiment pairs GPTQ and AWQ on byte-identical calibration samples across five seeds and
finds the method ordering reverses with the calibration draw in 5 of 8 confirmatory cells.

**Two of their framing points are load-bearing here and we adopt both.** *Detection is not
certification*: failing to reject a difference is not evidence of equivalence, and their registration
commits to not reading it that way. And their sizing equation *"answers how many items would this
benchmark need for an equivalence test to have 80% power, given how much models of this kind disagree
item-by-item. It does not answer how many items would certify the delta this source observed."* **Both
constrain how §5.3 and §5.4 may be read, and are restated there.**

**[QualityProxy]** tests whether quality metrics proxy for safety across GGUF, AWQ and GPTQ, finding
9 hidden-danger rows in 51 where quality is flat or improving while refusal degrades 12 to 68 points,
concentrated in AWQ and GPTQ. **Its safety measurement is a generative model's refusal, labeled by an
LLM judge** (primary `gemma3:12b`, secondary Claude Sonnet 4, Cohen's κ = 0.873).

**[MarginShrink]** supplies the mechanism this paper does not. Across **16 models from 8 families**
and four quantization schemes, plus activation and KV-cache axes, they show compression damage is
**proportional rather than additive**: the quantized margin follows *m′* = *c·m* + *b* + ε, the
surviving fraction *c* collapsing from a median 0.86 at 4 bits to **0.00 at 2**. A directional push
*b* accompanies it, producing **one-directional collapse** — 96% of should-call decisions flip while
80% of should-not-call survive. From the fitted law they derive a flip predictor accurate to a
**median 1.7 percentage points** on held-out cells. They also report that transferring the fitted
constants between models gives **18–33 point errors at 3 bits**, so the law must be re-measured per
model and bit-width.

**The gap all three leave is the same one.** A guard classifier is not a generator being judged and
not a next-token choice between two continuations; **its verdict is the measurement**. That removes
the judge from the loop — no grader variance, no κ — and it introduces an asymmetry none of the three
outcome variables has. **[MarginShrink]'s 16 models are all generative instruct models and no guard
classifier appears in any of the three studies.**

⚠️ **This bounds our contribution rather than widening it.** Directional compression damage is
[MarginShrink]'s (§5.2), and the mechanism for it is theirs (§7.7). What we add is the object, the
equivalence framing, and a measured floor — not the phenomenon.

**Prior results this paper depends on.** The corpus, the ladder and all 35 cells of per-item verdicts
come from earlier pre-registered companion experiments [Anon-A §5.4, §5.8]. The serving-floor
methodology is [Anon-A §5.10], and the hazard that motivated §5.5 is its `R42`.

## 3. Setting

**Object.** Five input-side guard classifiers from three publishers: Llama Guard 3 8B, ShieldGemma 2B
and 9B, Qwen3Guard-Gen 0.6B and 4B.

**Ladder.** Seven precisions from one publisher's conversion pipeline — `F16`, `Q8_0`, `Q6_K`,
`Q5_K_M`, `Q4_K_M`, `Q3_K_M`, `Q2_K` — so the conversion pipeline is held constant and only the
precision varies. Each model is compared **against its own `F16`**, never against another model.

**Corpus.** 1,000 items, 533 unsafe, 467 benign, identical across all 35 cells, byte-identical file
verified by hash. `num_ctx` 8192, `seed` 0, one serving stack throughout.

⚠️ **491 of the 1,000 items are adversarial by construction.** Absolute rates here are not deployment
rates and must not be quoted as guard performance. Every quantity below is a *within-model* delta, so
the corpus composition cancels.

## 4. Method

**Quantities**, fixed in a pre-registration frozen at `9f9d53d0` before any churn figure was computed:

- **net delta** — change in FNR and FPR, **reported separately, never pooled**
- **churn** — items whose binary verdict differs from that model's own `F16` on the same input
- **directional churn** — `unsafe→safe` and `safe→unsafe`, **always separately**
- **required n** — TOST sizing at declared margins, following [Certify]

**Certification sizing**, implemented as [Certify] §3.2 specify:

    sd_paired = sqrt(p_d)
    n_req = ceil( ((z_(1-alpha) + z_(1-beta)) * sd_paired / m)^2 )

at one-sided α = .05 (z = 1.6449) and 80% power (z = 0.8416). **We verified our implementation
numerically against their published Table 1** rather than against our reading of their abstract: their
`musr` row at a ±2pp margin reproduces to 520 against their printed 519, the residual being display
rounding of the discordance rate.

**Stability guard.** The churn ratio is undefined at a zero net delta and meaningless below a few
items. **Cells with a net delta under 3 items report raw counts with the ratio suppressed**, fixed
before any cell was computed.

**Unit of inference.** Items here are independent — 1,000 flat identifiers with distinct source
indices and no variant clustering — so paired item-level McNemar is valid and no cluster bootstrap is
used. This differs from other corpora in the companion studies and is stated because it changes what is valid.

## 5. Results

### 5.1 The ratio does not transfer, and Draft 1 compared the wrong number

`R1` [Certify] §4.2 is explicit that two different statistics are in play:

> These are ratios of medians, not medians of cellwise ratios, and the two summarise different
> things. The median among finite cellwise ratios is 3.85.
>
> — [Certify] §4.2. *Quoted verbatim; the source spelling stands.*

**Both are computed here against their matching figure:**

| statistic | guards (this work) | [Certify] |
|---|---|---|
| median of finite **cellwise** ratios | **1.86×** | **3.85×** |
| **ratio of medians** | **2.75×** | **5.40×** |

⚠️ **Draft 1 reported 1.4× against 5.40×** — a cellwise median against a ratio-of-medians, and
computed on a net delta partitioned by *verdict* direction rather than by *correctness*. Their net
delta is an accuracy delta. **Corrected, the gap is about 2×, not about 4×.**

⚠️ **We also tested whether arm separation explained the gap, and it does not.** The pre-registration
keeps the FNR and FPR arms apart, and arm separation prevents exactly the cancellation their critique
concerns — so we recomputed pooled. The conclusion survives the correction: **guard verdicts churn
roughly half as much, relative to net movement, as benchmark accuracy does.**

Offered as a hypothesis and not a finding: a binary verdict on a fixed input has less room for
opposing flips than a generated answer scored for correctness.

⚠️ **This does not weaken their argument; it locates it.** Cancellation is still present at 1.86×, and
a guard benchmark reporting one pooled number still hides it.

### 5.2 Direction is a model property, not a bit-width property

`R2` Directional churn pooled over the ladder:

| model | unsafe→safe | safe→unsafe | share u→s | reading |
|---|---|---|---|---|
| **shieldgemma-9b** | **144** | **4** | **0.97** | **safety-adverse** |
| llamaguard3-8b | 78 | 76 | 0.51 | symmetric |
| qwen3guard-06b | 247 | 306 | 0.45 | symmetric |
| shieldgemma-2b | 56 | 71 | 0.44 | symmetric |
| **qwen3guard-4b** | **15** | **30** | **0.33** | **usability-adverse** |

**The same seven-precision ladder drives two models in opposite directions.** ShieldGemma 9B loses
almost exclusively unsafe detections; Qwen3Guard 4B almost exclusively over-blocks.

`R3` **And one model reverses within its own ladder.** ShieldGemma 2B is *purely* usability-adverse at
`Q4_K_M` (0 unsafe→safe, 18 safe→unsafe) and at `Q3_K_M` (0 against 41) — then flips at `Q2_K` to
**47 unsafe→safe against 1**. **Direction is not even monotone in precision within a single model.**

**Why this is unavailable to [Certify]'s instrument, and to [QualityProxy]'s.** Their outcome is
symmetric: an item going correct→wrong is the same kind of event as wrong→correct, and a churn count
is the natural summary. **A guard's two directions have opposite consequences**, so a single churn
number for ShieldGemma 9B — 148 items — describes a model that has become materially less safe and one
that has become materially noisier equally well. **It is the wrong summary, and only a guard-shaped
outcome variable exposes that.**

⚠️ **Directional compression damage is not new, and [MarginShrink] must be credited for it.** They
fit a **directional push** term *b* alongside a margin-shrinkage coefficient, and report
**one-directional collapse** at the bit-width where damage begins: 96% of should-call decisions flip
while 80% of should-not-call survive, so a compressed agent **stops acting rather than acting wrongly**.
They also measure safety-refusal loss by model size — a 1.7B model loses almost all refusals at 3
bits, a 4B some, a 32B none.

**What is left to us is narrower than "direction," and we state it as the narrower thing.** Their *b*
is fitted per model, decision family and bit-width, and their directional result is *within* a model
across decision types. **Ours is across models on one decision type**: the same seven-precision ladder
drives ShieldGemma 9B and Qwen3Guard 4B in **opposite** directions on the same corpus. And
ShieldGemma 2B **reverses within its own ladder**, which is permitted by their per-cell fit — a sign
change in *b* between bit-widths — but is not something their reported results exhibit or predict.

**§5.8 returns to this and fits *b* directly.** A sign reversal within one guard's ladder is not
merely permitted by their model; **we measure it, in both guards we instrument.** ⚠️ On a different
stack, so it supplies the *shape* of an explanation for this table rather than a fitted account of it.

### 5.3 What the McNemar column may not be used for

`R4` Per-cell McNemar exact tests are reported in the artifact. ⚠️ **A large *p* here is not evidence
of equivalence**, and we adopt [Certify]'s registered commitment verbatim: *failing to find evidence
of a difference is not evidence of equivalence; with a small enough evaluation, nothing is
detectable.* The cells with high *p* are cells where this evaluation cannot detect a difference,
which is a statement about the evaluation. §5.4 is the instrument that answers the other question.

### 5.4 Certification: the requirement tracks churn, not guard quality

`R5` Items required to certify equivalence at a declared margin, at the deployed default `Q4_K_M`:

| model | `F16` FNR | churn rate | **n @ ±1pp** | n @ ±2pp |
|---|---|---|---|---|
| shieldgemma-2b | **0.8574** | 0.0180 | **1,113** | 279 |
| llamaguard3-8b | **0.2795** | 0.0180 | **1,113** | 279 |
| shieldgemma-9b | 0.5047 | 0.0170 | **1,052** | 263 |
| qwen3guard-06b | 0.0507 | 0.0110 | 681 | 171 |
| qwen3guard-4b | **0.0281** | 0.0040 | 248 | 62 |

`R6` **[Certify]'s central conceptual point reproduces in a new domain.** They show the requirement is
set by churn rather than by benchmark difficulty — MMLU needs three times GPQA's items despite being
the easier task. **The guard analog is sharper because the quality gap is larger.** ShieldGemma 2B
misses 85.7% of this corpus and Llama Guard 3 misses 28.0%; **they require exactly the same evidence**,
1,113 items. Qwen3Guard 4B, which misses 2.8%, requires **a quarter of that**. **A practitioner cannot
size a guard equivalence evaluation from the guard's accuracy, its size, or its family. Only from its
churn.**

`R7` **Three of five models need more than the 1,000 items this evaluation ran** to support a ±1pp
claim. That is a fact about the evaluation, not a defect in the models.

⚠️ **What this table is not.** Following [Certify] §3.2, it is the planning size for 80% power under
an assumed **true difference of zero**. **It does not tell you how many items would certify the delta
we actually observed**, and must not be read that way. Their §3.6 adds the constraint Draft 1 missed:
**meeting the count makes the test informative, it does not certify anything on its own — the test
still has to be run and to pass.** §5.5 runs it.

⚠️ **Their §3.5 also fixes which path we are on.** The guard ladder has no row in their Table 1, and
for a benchmark with no row their step 2 prescribes measuring discordance on your own pair and using
their equations directly. **That is what we did**, so the figures above are point requirements from
one observed discordance per model — not the p25/median/p75 band their families carry, and not an
extrapolation from their atlas.

### 5.5 The test, actually run — and a gray zone that is empty

⚠️ **Draft 1 reported required sample sizes and stopped there.** [Certify] §3.6 forecloses that:
*"any claim that a model meeting these counts is equivalent [is not supported], because meeting the
count makes the test informative, and the test still has to be run and to pass."* **We ran it.**

`R8` **The framework applies to guards by an identity worth stating.** Their §3.5 requires only that
the harness assign each item a correct-or-incorrect state, and explicitly excludes LLM-as-judge
ratings, graded scores and perplexity measures. A guard verdict qualifies — and **for binary
classification against a binary label, verdict disagreement and correctness disagreement are the same
event**, because differing verdicts mean exactly one is right. **Our churn is therefore exactly their
`p_d`.** We assert this in code rather than assume it: it holds in all 30 cells.

`R9` **TOST at the registered ±2pp margin, run on all 30 cells**, with the 90% two-sided interval on
the paired accuracy delta required to fall inside the margin. Placed on their Table 2 scale:

| population | certifiable @ ±2pp | detectable (McNemar *p*<.05) | **gray zone** |
|---|---|---|---|
| [Certify] S1 — 1,398 cells | 4.9% | 26.5% | **69.2%** |
| [Certify] S2 — 309 cells | 17.2% | 6.1% | **77.7%** |
| **P8 guard ladder — 30 cells** | **70.0%** | **30.0%** | **0.0%** |

**The gray zone is empty.** [Certify]'s empirical core is that the modal compressed-model cell is one
where *"the evaluation cannot answer the question the release note answers"* — 69.2% and 77.7% of
their two strata. **For guard classifiers at n = 1,000, no cell is in that state.** Every one is
either provably equivalent at the margin or detectably different.

**This is a contribution to their framework rather than a challenge to it**, and it follows directly
from §5.1: the requirement scales with churn, guards churn about half as much, and 1,000 items is
therefore enough where for a general-model benchmark it is not. **Certifying a quantized guard is
cheap. Certifying a quantized general model is not.**

⚠️ **A cell can be both certifiable and detectable** — a real difference, provably smaller than the
margin — so the shares do not sum to one. At the stricter ±1pp margin the certifiable share falls,
which is §5.4's point restated: the margin is a declared choice with quadratic cost.

`R10` **Their §4.3 phenomenon occurs more often in guards and matters less.** They report 145 of 1,707
cells (8.49%) scoring *identically* to baseline while still disagreeing item by item, at a median
churn of 0.0720. **Four of our 30 cells (13.3%) move accuracy by under one item while churning** —
proportionally more — but at a median churn of **0.0060, an order of magnitude smaller**. The
cancellation is real in guards and its magnitude is not.

### 5.6 A concern of ours, tested and refuted

`R11` Against the companion studies' stratified serving-noise floor of 0.09% [Anon-A §5.10], 29 of 30 cells
clear. ⚠️ **That comparison is nearly vacuous at n = 1,000**: 0.09% is 0.9 items, so any cell with a
single churned item passes. It was run as pre-registered and it decides almost nothing.

`R12` ⚠️ **We then raised a concern that would have undercut the entire paper.** [Anon-A] `R42` records
that the floor is probably not one number: on sets **selected by a prior verdict** it ran **1.0–5.7%**,
which is 10–57 items here. Against that floor **27 of 30 cells do not clear**, and every deployed-default
`Q4_K_M` effect in §5.2 would be indistinguishable from serving noise.

**Rather than argue which floor applies, we measured it** (addendum `69f3028f`, frozen before the
runs). Eight same-configuration replicates — identical model, quantization, corpus, seed, context,
separate containers. **Qwen3Guard 4B at `Q4_K_M` was chosen because it had the lowest churn on the
entire ladder, making it the case where a floor most plausibly explains the effect.** Choosing the
condition that most favors the null was deliberate and was stated in the addendum before the runs.

`R13` **The floor on this corpus is 0.107% mean pairwise disagreement — 1.07 items in 1,000 — with
just 2 items ever unstable across all eight runs** (Wilson 95% [0.055%, 0.726%]).

**That is the stratified figure, not the borderline one. Our concern was wrong.** Adversarial
*weighting* does not raise the floor the way verdict *selection* does: the borderline sets were
borderline because every item had been caught and then evaded, which selects for proximity to a
decision boundary. A corpus that merely contains adversarial text does not.

**The pre-registered conclusion stands, now against a floor measured on the corpus the claim is made
on rather than imported from another one.**

⚠️ **It stands narrowly for the condition measured.** A 4-item effect against 2 ever-unstable items is
a factor of two — above the floor, not comfortably. The models showing 17–18 items at `Q4_K_M` are
clearly above **if their floors are comparable, and floors are model-dependent** [Anon-A `R41`], so that
is an assumption.

### 5.7 Ladder position

`R14` Churn by precision:

| model | Q8_0 | Q6_K | Q5_K_M | Q4_K_M | Q3_K_M | Q2_K |
|---|---|---|---|---|---|---|
| llamaguard3-8b | 1 | 8 | 14 | 18 | 29 | 84 |
| qwen3guard-06b | 4 | 2 | 13 | 11 | 38 | **485** |
| qwen3guard-4b | 0 | 2 | 2 | 4 | 7 | 30 |
| shieldgemma-2b | 3 | 6 | 11 | 18 | 41 | 48 |
| shieldgemma-9b | 6 | 8 | 7 | 17 | 26 | 84 |

Churn rises with compression, as expected, and **Qwen3Guard 0.6B at `Q2_K` churns 485 of 1,000** — a
collapse rather than a degradation. **Reported last because it is the question a reader assumes and it
is not the finding.**

### 5.8 The mechanism reaches guards — measured, not assumed

⚠️ **An earlier draft of this paper said we could not test this. We since did.**
[MarginShrink]'s law is fitted on **16 generative instruct models** where every decision is a
next-token choice between two continuations. **No guard classifier appears in their study, nor in
[Certify] or [QualityProxy].** A guard's verdict *is* the decision rather than a token inside a
generation, so whether the law reaches that object was untested by anyone.

**Pre-registered at `34dc31e7` before any logit was captured.** Two guards × seven precisions
× 1,000 items, RTN quantization at group size 64, served through transformers. Zero null margins.

⚠️ **These cells are not comparable to the ladder in §5.1–§5.7, and the
pre-registration said so in advance.** Different serving stack — transformers against
Ollama/GGUF — and a different quantizer — RTN against K-quants. **Only the law is
comparable.** The GGUF stack cannot expose logits, so a margin cannot be measured on it at all; that
is why this could not simply be run on the cells above. **What follows establishes that the law
governs guard classifiers as a class. It does not establish that these coefficients describe the
GGUF cells.**

`R15` **H1 — the functional form transfers.** Multiplicative beats constant-additive by BIC in
**5 of 6 cells in both guards**. The single additive win in each model falls at a precision where
there is essentially no damage — 5 bits for the 0.6B, 8 bits for the 4B — where the two
accounts are near-indistinguishable.

`R16` **H2 — the collapse is real; the registered check was the wrong instrument for it.** The
surviving fraction *c*:

| bits | Qwen3Guard-0.6B | Qwen3Guard-4B |
|---|---|---|
| 8 | 0.996 | 0.999 |
| 6 | 1.012 | 1.013 |
| 5 | 0.999 | 0.986 |
| 4 | **0.876** | 0.955 |
| 3 | **0.014** | **0.680** |
| 2 | **0.006** | **0.003** |

⚠️ **The pre-registered check was strict monotonicity in *c*, and it fails in both
models** — *c* rises from 0.996 to 1.012 between 8 and 6 bits, with standard errors of 0.0007
and 0.0014, so the rise is real rather than noise. **Reported as registered, and as failed.**

**The substantive claim nonetheless holds, and the registered test does not capture it.** The wiggle
sits at precisions where *c* ≈ 1 and nothing is damaged; the collapse it was meant to detect is
unmistakable below 4 bits. **This is a point-estimate ordering check firing on a real but immaterial
movement**, and the standing correction applies: register the test, not the direction.

**The collapse point is model-dependent, and the smaller guard fails a full bit earlier.** The 0.6B
is already destroyed at 3 bits (*c* = 0.014) where the 4B retains two-thirds of its margin
(*c* = 0.680). Both reach *c* ≈ 0 at 2 bits, matching [MarginShrink]'s reported median of 0.00.

`R17` **H3 — the flip predictor transfers, at lower error than in their setting.** With
(*c*, *b*, σ) fitted on **margins only and never on flips**, their predictor gives a mean
absolute error of **0.75 percentage points** for the 0.6B and **0.94** for the 4B, against their
**1.7pp median** across 1,270 cells, and inside the pre-registered 5pp bound.

**This is expected rather than impressive.** A guard's decision is a single binary verdict on a fixed
input, so there is less for the residual to absorb than in a next-token choice inside a generation
— and **fewer cells also means less opportunity to be wrong.**

`R18` **H4 — direction is model-specific and reverses within a ladder.** The fitted push *b*:

| bits | Qwen3Guard-0.6B | Qwen3Guard-4B |
|---|---|---|
| 8 | +0.090 | +0.050 |
| 6 | +0.080 | +0.214 |
| 5 | +0.754 | +0.448 |
| 4 | **−0.348** | +0.136 |
| 3 | **−0.148** | +0.058 |
| 2 | **+1.988** | **−1.120** |

Positive *b* pushes toward **Unsafe** — safety-conservative, over-blocking. Negative pushes
toward **Safe** — safety-adverse, admitting harm. **The two guards disagree in sign at 4 and 3
bits**, and **both reverse sign within their own ladder**: the 0.6B at 4 bits and again at 2, the 4B
only at 2.

**§5.2 observed exactly this behaviorally and could not explain it.** ShieldGemma 2B is purely
usability-adverse at `Q4_K_M` and `Q3_K_M`, then 47-to-1 safety-adverse at `Q2_K`. **The fitted *b*
is the shape of the explanation — a directional push whose sign is not fixed across
precisions.**

⚠️ **The shape, not the instance.** ShieldGemma is not among the two guards instrumented
here, and the stack differs. **This makes the mechanism available to §5.2; it does not fit it.**

**None of the law is ours** (§1). What is ours is the measurement that it reaches this object,
and the negative result in `R16`.

## 6. What a deployer should take from this

**Ask which direction, not how much.** A single churn figure for ShieldGemma 9B is 148 items and tells
you nothing you can act on; the decomposition — 144 unsafe→safe against 4 — tells you the model has
become less safe rather than noisier. **Any guard quantization report that does not separate the two
directions is withholding the operative number.**

**Do not infer direction from precision.** ShieldGemma 2B is over-blocking at `Q4_K_M` and
under-blocking at `Q2_K`. **The ladder position does not tell you which failure you are buying.**

**Size the evaluation from churn, and measure churn first.** Guard accuracy does not predict the
requirement: our worst and mid-range guards need identical evidence (§5.4).

**Declare a margin.** [Certify]'s audit found none of 16 eligible published equivalence claims did.
Their five-line standard applies here unchanged: declare a margin, run the paired test, report churn
beside net delta, cite the sample size you met, release per-item outputs.

**Flip risk is predictable from margins, without running the ladder.** [MarginShrink]'s
predictor, fitted on margins alone, hit guard flip rates to under one percentage point
(§5.8). **If your serving stack exposes logits, you can estimate what a precision will cost
you before you deploy it** — and if it does not, that is itself a reason to prefer one that
does.

**And measure your own floor.** Ours differed by more than an order of magnitude depending on which
prior corpus we imported it from, and only measurement settled it (§5.5).

## 7. Limitations

1. **The instrument is not ours** (§0, §1), and neither is the cross-scheme audit.
1b. ⚠️ **We do not extrapolate from their atlas, and may not.** [Certify] §4.4 and §9 are explicit
   that it is *"the public record of compression evaluation, not a census of quantization"* —
   community quantizations of 2023-era models conditioned on leaderboard coverage, plus one vendor's
   releases evaluated by that vendor. **Our comparisons against their S1/S2 shares in §5.5 are
   against that record, not against quantization in general**, and our own requirement figures come
   from discordance we measured, not from their rows.
2. **`F16` is the reference, not the truth.** Every delta is movement away from a model's own
   half-precision behavior, which is not itself validated as correct.
3. **One conversion pipeline, one serving stack.** All ladders come from a single publisher's GGUF
   conversions served through one stack, deliberately, to hold the pipeline constant. **Nothing here
   generalizes to AWQ, GPTQ or NF4**, and §0 explains why we did not extend.
4. **The floor is measured for one model at one precision** (§5.5). Floors are model-dependent, so
   the other four models' comparisons rest on an assumption.
5. **The corpus is adversarially weighted** (§3), so absolute rates are not deployment rates.
6. **H1's direction was known before the study was designed** (§1).
7. **A mechanism exists and it is not ours; we do not test whether it reaches guards.** ⚠️ **An
   earlier draft of this paper claimed the direction was unexplained. That was wrong.**
   **[MarginShrink] supply the mechanism**: compression damage is **proportional, not additive** —
   the quantized margin follows *m′* = *c·m* + *b* + ε, with the surviving fraction *c* collapsing
   from a median 0.86 at 4 bits to 0.33 at 3 and **0.00 at 2**. Confident decisions therefore lose the
   *same fraction* of their margin as marginal ones and cross zero too, which refutes the fixed-noise
   intuition; they exclude that whole class with a parameter-free bound that **107 of 183 measured
   steps violate**. The directional push *b* is the direction term. From this they derive a flip
   predictor, `P(flip|m) = Φ(−(cm+b)·sign(m)/σ)`, fitted on margins rather than flips, with a
   **median held-out error of 1.7 percentage points** across 1,270 cells.
   **We tested whether that law governs guard classifiers, and it does** (§5.8). Their 16
   models are all generative instruct models and every decision is a next-token choice between two
   continuations; **no guard classifier appears in their study**, and a guard's verdict is the
   decision rather than a token inside a generation. The functional form, the collapse and the flip
   predictor all transfer, the last at under 1pp mean error.
   ⚠️ **But on a different serving stack, and this bounds what §5.8 may be used
   for.** Margins require logits, which the GGUF stack does not expose, so the test ran on
   transformers with RTN quantization. **The law is established for guard classifiers as a class;
   that it describes the specific cells in §5.1–§5.7 remains an inference.**
   ⚠️ **And its pre-registered monotonicity check failed**, reported as failed in `R16`.
   **Two guards, one family, one corpus, one quantizer.** ShieldGemma and Llama Guard are not
   instrumented, and they are the two families §5.2 finds most directionally extreme. **We fit
   the push *b*; we do not explain why it points where it does, or why it reverses.**
   For completeness, the probes that *did* fail are [QualityProxy] §4.4's four: entropy shift
   (*p* = 0.606), calibration drift (all |*r*| < 0.09), refusal-direction geometry (cosine above 0.97
   in every quantized cell), and safety-neuron error — real at 1.39×, *p* = 4.89 × 10⁻⁷, but
   **global rather than regime-specific**.
8. **Five models, three families.** ShieldGemma contributes two of the five, and its two members
   supply both the most safety-adverse row and the mid-ladder reversal, so §5.2's spread rests
   partly on one family.
9. **Single seed per cell** for the 35 ladder cells; only the floor condition was replicated.

## 8. Artifact

Per-item verdicts for all 35 cells and all 8 floor replicates; the corpus with its hash; the
pre-registration and its addendum with both hashes; the analyzer, the pooled-ratio and dual-floor
follow-up, and the floor analyzer. **Every statistic in §5.1 through §5.4 and §5.6 is reproducible
from the released verdicts with no GPU.**

**§5.8 adds** the per-item decision margins for both guards at all seven precisions, its
pre-registration and hash, the margin-capture job and the analyzer — which, as the
pre-registration required, **was written before any logit was captured**.

**Total new compute: 30.4 GPU-minutes on A10G for the floor replicates ($0.56), plus the
§5.8 margin capture on A100-40GB (approximately $0.70).** The 35-cell
analysis cost nothing — it is a re-analysis of verdicts collected by earlier companion experiments. **The pipeline had estimated ~20 GPU-hours; the literature check removed the part that would
have consumed them, and [Certify]'s calibration-draw result showed that part would have been an
artifact.**

## References

[Certify] A. Singh. *Certifying Compressed Language Models: An Audit and a Statistical Toolkit.*
Georgia Institute of Technology. arXiv:2608.15046v1 [cs.LG], 15 August 2026.

[QualityProxy] S. Kadadekar. *Quality Is Not a Safety Proxy Under Quantization.* Independent
Researcher, NYU. arXiv:2606.10154, 8 June 2026.

[MarginShrink] Z. Wu, S. Dhiman, and A. Koshiyama. *Which Decisions Low-Bit Quantization Breaks, and
How to Predict Them.* Holistic AI; UCL Centre for Artificial Intelligence. arXiv:2608.06564, 6 August
2026. Under review, Third Workshop on Uncertainty-Aware NLP (UncertaiNLP) at EMNLP 2026,
non-archival track.

[Anon-A] Anonymous. *Companion submission; title withheld for review.* Under review, 2026. — source of the corpus, the ladder, and all 35 cells of per-item verdicts.

---

### Production notes

- **Draft 4 folds in the margin-capture experiment (§5.8).** Draft 3's §7.7 said the mechanism
  question was *"a concrete next experiment"*; it has now been run and the section is rewritten.
  ⚠️ **Two things must not be lost in later edits**: the result is on a *different serving
  stack* (transformers/RTN, because GGUF cannot expose logits), so it establishes the law for guards
  as a class and not for the cells in §5.1–§5.7; and the **pre-registered monotonicity check
  failed** and is reported as failed in `R16`. **Both are load-bearing caveats, not hedges.**
- ⚠️ **The abstract said "Three results" while listing four.** Fixed in Draft 4; it now says
  five. Worth a check on every future draft that the count matches the list.
- **The LaTeX and anonymized builds predate §5.8** and must be regenerated before submission.

- ~~Blocking: complete the read of [Certify].~~ **Done, and it forced Draft 2.** Three corrections,
  every one against us: the comparison statistic (§5.1), reporting sizing without running the test
  (§5.5), and the population we may extrapolate from (§7.1b). It also produced §5.5's empty gray
  zone, which is now the strongest result in the paper and which a partial read could not have
  reached.
- ⚠️ **One quotation retains British spelling** ("summarise", §5.1). It is verbatim from [Certify]
  §4.2 and is protected by the standing quotation carve-out — **flagged, never silently edited**.
- ~~[QualityProxy] is still read as a structured summary.~~ **Closed.** Read in full text.
  **The 1.39× figure verified exactly** — *p* = 4.89 × 10⁻⁷, across the completed AWQ/GPTQ cells,
  and explicitly *"global rather than regime-specific."* The read also supplied §7.7's stronger form
  (their four probes all failed, refusal-direction cosine stays above 0.97) and §1.3's second
  named-extension framing. **No read debt remains on either source.**
- **Consider whether the title should change.** It leads with directional churn (§5.2), which is the
  guard-specific contribution. The empty gray zone (§5.5) is arguably the stronger result and is a
  direct contribution to [Certify]'s own framework. Both are defensible; the current title is not
  wrong, only no longer obviously the best.
- ~~Venue: short measurement paper or workshop. The instrument is prior art.~~ **Resolved: USENIX
  Security.** The earlier note reasoned from the *instrument* to the *venue*, which conflates two
  different things. The instrument is prior art and §1 says so on its first line. **The findings are
  not**, and neither is the object: no prior work measures a guard classifier, which is the component
  in the request path. Two of the three contributions are work the sources **named as outstanding**
  ([QualityProxy] §5.3's equivalence gap; [Certify] §3.6's requirement that the test be run), and
  §5.5's empty gray zone is a domain-level result about where their evidential crisis does and does
  not apply. **A full-venue submission rests on the findings, not on who built the ruler.**
- ~~Anonymization for double-blind not yet performed.~~ **Done.** Built two-column for USENIX,
  anonymous in both PDF metadata and extracted text, verified by `verify_submission.py`.
