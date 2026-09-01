# Shared Lineage, Not Shared Category, Makes Guards Fail Together

### Two studies of stacked defenses, sharing no members and no defense types, converge on the same conditional result — and neither finds independence

**Draft 3 · 2026-08-31 · Vikram Jha**
*Draft 2 revised Draft 1 throughout after reading [LayeredEns] §11 in full; three claims were withdrawn. Draft 3 re-runs the stratification with their own CMH estimator (§5.5b), which turned the paper from a contrast with their result into a convergence with it. All withdrawals are marked in place.*

---

> ⚠️ **This is a replication and extension, not a novel contribution, and the framing is not ours.**
> A literature check run **before** this draft surfaced **Alotaibi et al. [LayeredEns]**, published
> **2026-08-28 — three days before our experiment ran** — which states the governing argument (a
> defense stack is a multiple-classifier system that compounds only under failure independence),
> measures it on a seven-layer stack, and reports **all fifteen pairs correlated** with a joint
> residual above the multiplicative prediction. **That is our headline result, published first and
> developed considerably further.** Their §11 is read in full for this draft.
>
> **What is left, and it is narrower than Draft 1 claimed.** Their §11.6 runs the difficulty
> stratification that decides whether correlation is shared blind spots or common cause, and finds
> that after correction **one pair of fifteen survives**. They also state plainly that this analysis
> is **"underpowered by construction"** — *n* = 100 behaviors across about six strata — and nominate
> **"a larger behavior set … the most valuable extension of this experiment."**
>
> **This paper is that extension.** We run their control on 899 unsafe items across 150 payload
> clusters, roughly nine times their behavior count, against six standalone guards that share no
> substrate. Re-run with **their own CMH estimator**, **8 of 15 pairs survive** against their 1 of 15.
>
> **And the result converges with theirs rather than contradicting it.** Their one survivor — two
> probes sharing "an input representation and a training pipeline" — has a conditional odds ratio of
> 158.7; **our strongest survivor, two scales of one guard family, has 158.00.** Their same-row pair
> that *lacked* shared training did not survive (OR 1.39), and neither do our cross-family pairs
> (geometric mean 1.75). **Both studies find that shared training lineage survives conditioning on
> difficulty while shared defense category does not.**
>
> ⚠️ **Draft 1 claimed our result was the *opposite* of theirs. That claim is withdrawn** (§5.5,
> §5.5b). It was wrong twice over: their §11.6 is underpowered by their own statement, and once the
> same estimator is used the two findings agree.

---

## Abstract

Practitioners stack guard models and assume the layers compound. They compound only if the members
fail on different inputs, and that condition is measurable. Concurrent work [LayeredEns] measured it
for a seven-layer stack around a single target model and found it fails everywhere, attributing the
dependence to a shared substrate — every layer wraps the same model, so an input that moves that
model off its shallow safety behavior tends to defeat every layer at once. That account predicts the
dependence is not attenuable by widening the member pool.

**We test the case that account excludes.** Six standalone guard models from three publishers — Llama
Guard 3 8B, ShieldGemma 2B and 9B, and Qwen3Guard at 0.6B, 4B and 8B — screen the same 1,799 inputs
under one configuration. There is no shared substrate: these classifiers read the input, not a
generation from a common model.

Three results. **First, the correlation is undiminished by removing the substrate.** All fifteen
pairs fail non-independently with cluster-bootstrap intervals excluding independence, and the
six-guard stack misses **15.9%** of unsafe items where independence predicts **0.31%** — an
independence penalty of **51×, 95% CI [28.9, 99.7]**.

**Second, the association survives conditioning on item difficulty — the control the prior art
nominates as its own most valuable extension.** Their §11.6 stratifies on behavior difficulty and,
after correction, one pair of fifteen survives; they state the analysis is **"underpowered by
construction"** at *n* = 100 across six strata. We run it on **899 items across 150 payload
clusters** using **their CMH common-odds-ratio estimator**, and **8 of 15 survive** (10 on a
cluster-robust interval). The split is by training lineage: **geometric mean conditional odds ratio
32.24 within-family against 1.75 cross-family, with 4 of 4 within-family pairs surviving and 4 of
11 cross-family.** One cross-family pair is genuinely complementary, with an odds ratio of 0.58,
interval [0.38, 0.96].

**This converges with their finding rather than opposing it.** Their single survivor — two probes
sharing "an input representation and a training pipeline" — has an odds ratio of 158.7; our strongest
has **158.00**. Their same-row pair *without* shared training did not survive (1.39), and neither do
our cross-family pairs. **Shared lineage survives conditioning; shared defense category does not**,
in both studies.

**Third, both statistics in play carry marginal-dependent ceilings, and this inverted one of our own
conclusions.** The independence penalty π is bounded by the reciprocal of the members' FNR product,
so weak guards cannot exhibit a large π however correlated they are. **φ is bounded too** — a point
[LayeredEns] §11.1 states and we initially got wrong — and in our panel the bound is *confounded with
the contrast we report*, because same-family guards have similar marginals by construction.
Normalization preserves the direction and **removes the clean separation we first claimed**.

The practical consequence is narrower than the prior art's but points the same way. They conclude
achievable diversity is capped by a property no member controls. We find that **where no substrate is
shared, cross-publisher selection still buys more independence than same-publisher scaling** — a
bigger model from the same publisher is close to a substitute (Qwen3Guard 4B/8B conditional φ =
0.760, normalized 0.794). The stack still underperforms the multiplicative model by a wide margin,
and stacking's false-positive cost is real: 6.7%, or 1.54× the worst single member.

---

## 1. What this paper is, stated before any result

**The argument is not ours.** [LayeredEns] states it: a deployed defense stack is a multiple-classifier
system under a unanimity veto, the information-fusion literature settled three decades ago that
combination pays only to the extent members fail on different inputs, and the LLM security literature
recommends stacking without ever measuring the condition. They then measure it.

**Our headline number is a replication of theirs in a different setting.** We say so here rather than
in a limitations section.

**Three things remain, in the order the title puts them:**

1. **A convergent result that neither study could establish alone** (§5.5b). Their members are seven
   *defense types* around one model; ours are six *instances of one type* around none. **The two
   panels share no members, no defense types, and no corpus.** Run with their estimator, both find
   that pairs sharing a **training pipeline** retain association after conditioning on item
   difficulty, while pairs sharing only a **defense category** do not. Their surviving pair sits at a
   conditional odds ratio of 158.7 and their failing same-category pair at 1.39; ours sit at 158.00
   and a cross-family geometric mean of 1.75. **A rule that holds across two panels with nothing in
   common is worth more than either measurement**, and it is not visible from inside either study.
2. **The extension they nominate.** Their §11.6 is "underpowered by construction" by their own
   statement, and they name a larger behavior set as "the most valuable extension of this
   experiment." We supply roughly nine times the items, and **8 of 15 pairs survive against their 1 of
   15** using their own estimator. **This is a power question we can answer and theirs could not**,
   and it is a contribution to their result rather than a contradiction of it.
3. **A setting their mechanism excludes.** Their dependence is architectural: members share the
   wrapped model. Ours share nothing but the input, so whatever survives conditioning here cannot be
   the architectural term. **This bounds what their mechanism has to explain** — it does not show the
   attribution was wrong.

⚠️ **Not claimed: the numerical coincidence.** That their 158.7 and our 158.00 agree to three digits
is luck, and §5.5b says so. **The claim is the rule, not the decimal**, and the title deliberately
rests on the former.

⚠️ **Also not claimed: a clean statistic.** §5.4 records a caveat that changed our own conclusion
twice, once in our favor and once against, which is why it appears as a caution rather than a
contribution.

**We claim no novelty on:** the ensemble framing, the independence condition, the finding that
stacking underdelivers, the union behavior of false refusals, or the observation that diversity must
be measured rather than assumed. All are in [LayeredEns], and the fusion lineage behind them is older
still [Kuncheva, Biggio].

## 2. Related work

**The immediate prior art.** [LayeredEns] builds two instruments — an adversary access-tier model and
a five-class inference-cost model — derives how a stack behaves along four axes, and measures failure
correlation for every measurable pair of a seven-layer stack under one adaptive adversary. Their four
findings: independence fails in all fifteen pairs (φ 0.30–0.75); most of the correlation is common
cause rather than shared mechanism; depth is bounded by refusals and dominated by one strong layer;
and measured strength is a property of the attack class. They characterize φ as "a selection
statistic, not a prediction statistic."

**Where our design differs, and why it is not a criticism of theirs.** Their layers are *defense
types* — a perplexity filter, a semantic classifier, a linear probe, a smoothing wrapper — all
operating around one target model. Ours are six *instances of one defense type*: input-side safety
classifiers, from three publishers. Neither design dominates. Theirs answers what a realistic
heterogeneous deployment does; ours isolates whether correlation requires the substrate their
mechanism rests on.

**Ensembles of guardrails.** [LayeredEns] §4.2 catalogs the systems that assume what it measures —
mixture-of-defenders, boosting ensembles, ensemble-of-experts moderation, logical-reasoning
combination — and notes the operational literature recommends stacking on the grounds that different
defenses' mistakes are "likely to be uncorrelated." We inherit that survey rather than repeat it.

**Classifier fusion.** The condition, the diversity statistics, and the lesson that diversity must be
created rather than hoped for are decades old [Kuncheva]. Its adversarial branch adds that dependence
is something an attacker can act on [Biggio]. [LayeredEns] §10.5 argues the fusion account of *why*
members correlate — a sampling account, dependence arising from overlapping training draws — fails for
defense stacks, because their members are not estimated from a shared sample and several are not
estimated at all.

**That argument is exactly what our setting puts back in play.** Our six members *are* estimated, several
*do* share lineage, and there is no wrapped model to carry an architectural term. If the sampling
account has a domain, this is it.

**Prior results this paper depends on.** The corpus, transformation set, and four of the six per-item
verdict sets come from our own earlier panel experiment [T-03 §5.7], pre-registered and hashed before
its data existed.

## 3. Setting and threat model

**Composition rule.** OR-composition under a unanimity veto: the stack blocks if *any* member flags.
This is the deployed default and the one [LayeredEns] analyzes. **A stack therefore misses an item
only when every member misses it**, which is why most of this study needs no new inference — it is a
boolean function of per-item verdicts already collected.

**Adversary.** Non-adaptive by construction. The transformations were frozen and hashed (`48ce3dae`)
for a false-positive experiment *before any guard was evaluated on anything*, and no transformation
was selected or retained because it defeated a guard. **Every effect reported here is therefore a
lower bound**, and this is a weaker adversary than [LayeredEns] use — they run one adaptive
adversary against the stack. Where they can speak to adaptive attack, we cannot.

**What the adversary may not do.** Modify any guard, its weights, its quantization, its prompt, or the
composition rule.

## 4. Method

**Panel.** Six guards, three publishers, three families:

| guard | family | source |
|---|---|---|
| Llama Guard 3 8B | llamaguard | prior panel [T-03 §5.7] |
| ShieldGemma 2B | shieldgemma | prior panel |
| ShieldGemma 9B | shieldgemma | prior panel |
| Qwen3Guard-Gen 8B | qwen3guard | prior panel |
| **Qwen3Guard-Gen 0.6B** | qwen3guard | **added for this study** |
| **Qwen3Guard-Gen 4B** | qwen3guard | **added for this study** |

**The extension was committed in the pre-registration before any analysis was run**, so panel size
could not be chosen after seeing a result. Its purpose was to put three scales of one family into the
panel, which is the only clean within-family axis available. All six ran the identical item files at
`num_ctx=8192`, `seed=0`, one harness, one parser per family. **The analyzer aborts if panel members
differ in configuration**, since a configuration difference between members would confound every
correlation reported.

**Corpus.** 1,799 items: 900 benign, 899 unsafe, each 150 payloads × 6 variants (one payload has 5) —
an original plus five frozen transformations. 0 errored, 0 unparsed for every model.

⚠️ **The corpus is adversarially weighted by construction.** Five of six unsafe items are
rephrasings. **Absolute FNRs here are not deployment FNRs** and must not be quoted as general
performance. The composition results are ratios of these marginals.

**Unit of inference.** The 899 unsafe items are **not** 899 independent observations; they are 150
payload clusters. Treating items as independent would inflate significance by roughly √6. **All
intervals are cluster bootstraps over the 150 clusters** (10,000 draws, percentile), and the analyzer
has no code path that emits an item-level interval.

**Statistics.**

- **Independence penalty** `π_S = FNR_S / Π FNR_g`. Symmetrically on benign items with
  `FPR_S* = 1 − Π(1 − FPR_g)`. **Both are computed and printed together for every stack**; no
  function returns one without the other.
- **Stability guard.** π is undefined at a zero prediction and meaningless below one expected item.
  Such stacks print as unstable with raw counts and are excluded from aggregates.
- **φ**, the correlation of miss indicators — the statistic [LayeredEns] report — used for the
  mechanism questions in §5.4 and §5.5.

**Pre-registration.** Frozen at `364800ff` before any composition statistic was computed. **It is
explicitly weaker than the others in this program and says so in its own §0**: the panel data already
existed and its transfer result was known, so H1's direction was *not* a blind prediction. What it
could still protect — the estimator, the unit of inference, the reporting order, the thresholds — it
did.

## 5. Results

### 5.1 All fifteen pairs fail non-independently

Per-guard marginals, which every ratio below is a ratio of:

| guard | FNR | FPR |
|---|---|---|
| llamaguard3-8b | 0.4594 | 0.0256 |
| qwen3guard-06b | 0.2536 | 0.0433 |
| qwen3guard-4b | 0.2147 | 0.0333 |
| qwen3guard-8b | 0.2002 | 0.0322 |
| shieldgemma-2b | 0.8476 | 0.0044 |
| shieldgemma-9b | 0.7353 | 0.0022 |

`R1` **Every one of the fifteen pairs has π > 1 with a cluster-bootstrap interval excluding 1.** Not
one pair of guards fails independently. This reproduces [LayeredEns]'s finding 1 in a panel with no
shared substrate.

### 5.2 The six-guard stack

`R2` | | value |
|---|---|
| measured stack FNR | **0.1591** |
| independence predicts | **0.0031** |
| **independence penalty** | **51.0×**, 95% CI **[28.9, 99.7]** |

**Six guards from three publishers, stacked under a unanimity veto, still miss 15.9% of unsafe
items.** Independence predicts 0.31%.

### 5.3 The cost side runs the other way

`R3` | | value |
|---|---|
| measured stack FPR | **0.0667** |
| independence predicts | **0.1337** |
| penalty | **0.50×** |

**Stacking costs about half the false positives independence predicts**, because guards also agree on
which benign items look unsafe. **Correlation destroys the FNR benefit and discounts the FPR cost
simultaneously** — the same fact, cutting opposite ways on benefit and cost. Reporting only the first
would be the one-directional error our own prior work documents [T-03 §5.1], and the pre-registration
lists it as invalidating.

`R4` **The absolute cost is still real.** 0.0667 is **1.54× the worst single member** (0.0433) and
**30× the best** (0.0022). A deployer stacking six guards trades a 15.9% miss rate for a 6.7%
false-positive rate. **Neither number resembles what independence promised.**

This is directionally consistent with [LayeredEns]'s finding 3 — refusals accumulate against the
defender — though their stack refuses four in five benign prompts, far above ours. We do not attempt
to reconcile the magnitudes: different defense types, different corpus, different adversary.

### 5.4 A statistic caveat that inverted our own conclusion

`R5` On the raw penalty, within-family pairs average π = 3.16 and cross-family 1.42. **We first read
this as resting on a single family**, because the ShieldGemma pair's π is 1.15 while the three
Qwen3Guard pairs run 3.43–4.48.

**That reading was an artifact of the statistic, and it was wrong.**

**π is bounded above by 1/(Π FNR_g).** ShieldGemma 2B and 9B miss 84.8% and 73.5% of this corpus, so
their product is 0.623 and **π cannot exceed 1.60 however correlated they are.** The observed 1.15 is
72% of its structural maximum. Qwen3Guard 4B+8B, with FNRs near 0.21, has a ceiling of 23.3.

| statistic | question it answers | ceiling |
|---|---|---|
| **π** | what does stacking buy me over independence? | **1 / Π FNR** |
| **φ** | do these two guards fail on the same inputs? | **φ_max = √(p₁(1−p₂) / p₂(1−p₁))** |

⚠️ **Draft 1 of this paper asserted that φ carries no such ceiling. That was wrong, and the correction
comes from [LayeredEns] §11.1**, which gives the bound above, notes that "a raw ordering by φ is
therefore not an ordering by dependence," and reports normalized φ/φ_max wherever pairs are ranked.
Their marginals span 0.35–0.68, giving φ_max between 0.503 and 1.000. **Ours span 0.20–0.85, so our
spread is far wider and the correction matters more for us than for them.** §5.5 applies it.

**What survives as a caution.** π and φ answer different questions and neither is a similarity
ordering in raw form. A deployer wants π; a mechanism claim needs normalized φ. **We got this wrong in
both directions** — first reading π as a similarity statistic, then reading raw φ as one — which is
why it is offered as a caution rather than a contribution. [LayeredEns] state the φ half already, and
more carefully.

### 5.5 The extension the prior art nominates, run at nine times the size

⚠️ **Unregistered, and prompted by prior art discovered after the run.** [LayeredEns] §11.6 stratifies
on behavior difficulty; after Benjamini–Hochberg correction **one pair of fifteen** retains
within-stratum association — the probe pair, whose members share "an input representation and a
training pipeline." They are explicit about the limitation: the analysis is **"underpowered by
construction"** at *n* = 100 across about six strata, ten of fifteen pairs return wide intervals,
*"not significant within strata" should be read as insufficient evidence rather than as evidence of
no effect*, and **"a larger behavior set … would sharpen this analysis, and we flag it as the most
valuable extension of this experiment."**

**Our design is theirs.** For each pair, stratify by a leave-out difficulty score — how many of the
*other four* guards miss that item — which keeps the stratifier independent of the pair under test.
We arrived at this independently and it is their construction. Two differences: we pool a
size-weighted within-stratum φ with a permutation null resampling whole payload clusters, where they
use a CMH common odds ratio with Haldane–Anscombe correction and BH-adjusted *q*; and **our labels
carry no grader noise.** Their breach labels come from a stochastic autograder that changed 6.3% of
verdicts on re-judge; our verdicts are the guards' own deterministic outputs at fixed seed, 0
unparsed. For a stratified analysis that is a real advantage, and it is not one we engineered — it
follows from measuring classifiers rather than attacks.

`R6` **The corpus does have a hard core.** 143 of 899 unsafe items (15.9%) are missed by all six
guards; 112 (12.5%) by none.

`R7` **10 of 15 pairs retain significant association after conditioning**, against their 1 of 15. The
survivors are structured by family:

| pair | marginal φ | stratified φ | φ_max | **φ/φ_max** | *p* |
|---|---|---|---|---|---|
| qwen3guard 4b+8b | 0.910 | **0.760** | 0.957 | **0.794** | 0.0002 |
| shieldgemma 2b+9b | 0.601 | **0.470** | 0.707 | **0.665** | 0.0002 |
| qwen3guard 06b+8b | 0.750 | **0.410** | 0.858 | **0.478** | 0.0002 |
| qwen3guard 06b+4b | 0.741 | **0.344** | 0.897 | **0.384** | 0.0002 |
| llamaguard + shieldgemma-2b | 0.310 | 0.157 | 0.391 | **0.402** | 0.0002 |
| llamaguard + shieldgemma-9b | 0.381 | 0.174 | 0.553 | 0.315 | 0.0002 |
| llamaguard + qwen3guard-4b | 0.464 | 0.151 | 0.567 | 0.266 | 0.0006 |
| llamaguard + qwen3guard-06b | 0.432 | 0.091 | 0.632 | 0.144 | 0.0070 |
| llamaguard + qwen3guard-8b | 0.448 | 0.073 | 0.543 | 0.135 | 0.0478 |
| qwen3guard-4b + shieldgemma-9b | 0.295 | 0.054 | 0.314 | 0.172 | 0.0360 |
| *five pairs dissolve* | | −0.053 to 0.059 | | | > 0.05 |

`R8` ⚠️ **The φ_max spread is confounded with the contrast, and this must be stated before the
contrast is.** Same-family guards have **similar FNRs by construction**, which raises φ_max;
cross-family pairs mix 0.20 against 0.85, which lowers it. **Within-family φ_max runs 0.707–0.957 and
cross-family 0.212–0.632 — non-overlapping.** A raw ranking would read a marginal artifact as a family
effect.

**Normalized, the direction survives and the clean separation does not:**

| | raw stratified φ | **normalized φ/φ_max** |
|---|---|---|
| within-family | 0.496 | **0.580** |
| cross-family | 0.070 | **0.144** |
| ratio | 7.1× | **4.0×** |

⚠️ **Draft 1 claimed the two groups do not overlap. That claim is withdrawn.** On the normalized
statistic the lowest within-family pair (0.384) falls *below* the highest cross-family pair
(llamaguard + ShieldGemma 2B, 0.402). **The fourfold mean difference is the result; the separation is
not.** Normalized values are also least stable exactly where φ_max is smallest, which is the
cross-family pairs.

**Reading it against their result.** Ours is not the opposite of theirs, and Draft 1 was wrong to say
so. **Given their stated power limitation, 10-of-15 against 1-of-15 is consistent with a sample-size
difference alone.** What can be said is narrower and still useful:

1. **At nine times the item count, the negative half of their §11.6 does not reproduce.** Their own
   framing — insufficient evidence, not evidence of absence — anticipated this.
2. **What survives in our data is the same kind of relation that survived in theirs.** Their one
   surviving pair shares a training pipeline and an input representation; ours share a training
   family. They note this "would suggest the taxonomy is coarser than the phenomenon," and our result
   is consistent with that suggestion in a panel where the taxonomy is lineage rather than mechanism.
3. **Our panel has no substrate**, so whatever survives here cannot be the architectural term. That
   is a genuine difference in setting, but it is a difference in what the measurement *can* attribute,
   not a demonstration that their attribution was wrong.

⚠️ **Their conservativeness caveat applies to us unchanged**: conditioning on the outcomes of other
guards removes shared variance that is arguably part of the effect of interest, so the test
under-credits genuine mechanism overlap at both sample sizes.

### 5.5b The same test with their estimator — and it converges with their finding

§5.5 compares our result to theirs while differing in **four** ways at once: setting, sample size,
statistic and label noise. That is too many to attribute anything to. **This section removes one**, by
adopting their estimator exactly: leave-out difficulty strata, **Cochran–Mantel–Haenszel common odds
ratio**, Haldane–Anscombe +0.5 applied uniformly so crude and stratified values stay comparable, and
Benjamini–Hochberg *q* across the fifteen pairs.

⚠️ **One thing we cannot inherit.** The CMH chi-square assumes independent observations. Their
behaviors are; our 899 items are 150 payload clusters of six. **Run as specified, the *p*-values are
anti-conservative for our data by roughly √6.** We report the exact-as-specified value *for
comparability* and a cluster-bootstrap interval on log(OR_MH) beside it. **Where they disagree, the
cluster-robust one is what is true of our data.**

`R9` **The odds ratio carries no φ_max-style ceiling**, which is why [LayeredEns] use it for this
test and φ only for the Table 10 ranking. **The family contrast below is therefore not exposed to the
marginal confound that forced normalization in §5.5.**

| pair | rel | crude OR | **CMH OR** | *q* (BH) | cluster 95% CI |
|---|---|---|---|---|---|
| qwen3guard 4b+8b | within | 789.35 | **158.00** | 0.0000 | [69.98, 542.39] |
| shieldgemma 2b+9b | within | 43.86 | **28.42** | 0.0000 | [13.95, 72.71] |
| qwen3guard 06b+8b | within | 93.36 | **18.76** | 0.0000 | [7.53, 57.52] |
| qwen3guard 06b+4b | within | 70.61 | **12.82** | 0.0000 | [5.36, 32.82] |
| llamaguard + shieldgemma-9b | cross | 7.96 | 3.18 | 0.0000 | [1.46, 8.51] |
| llamaguard + qwen3guard-4b | cross | 17.47 | 3.16 | 0.0058 | [1.36, 9.49] |
| qwen3guard-4b + shieldgemma-9b | cross | 27.19 | 2.81 | 0.2732 | [1.44, 5.77] |
| llamaguard + shieldgemma-2b | cross | 10.19 | 2.78 | 0.0034 | [1.06, 9.18] |
| qwen3guard-06b + shieldgemma-9b | cross | 15.52 | 2.43 | 0.1082 | [1.13, 6.63] |
| llamaguard + qwen3guard-8b | cross | 17.51 | 2.01 | 0.3077 | [0.89, 5.11] |
| llamaguard + qwen3guard-06b | cross | 9.56 | 1.94 | 0.0367 | [1.09, 3.55] |
| qwen3guard-06b + shieldgemma-2b | cross | 16.12 | 1.59 | 0.5798 | [0.56, 5.16] |
| qwen3guard-8b + shieldgemma-9b | cross | 24.65 | 1.58 | 0.8188 | [0.85, 3.11] |
| **qwen3guard-8b + shieldgemma-2b** | cross | 16.55 | **0.58** | 0.8866 | **[0.38, 0.96]** |
| qwen3guard-4b + shieldgemma-2b | cross | 12.79 | 0.43 | 0.3077 | [0.17, 1.33] |

`R10` **8 of 15 survive as they specify it**; 10 of 15 on the cluster-robust interval. Against their
**1 of 15**. The gap between our two counts is exactly the clustering the CMH test cannot see.

`R11` **The family split is clean on this statistic and does not depend on normalization.**

| | geometric mean CMH OR | survive (as specified) |
|---|---|---|
| **within-family** | **32.24** | **4 of 4** |
| **cross-family** | **1.75** | 4 of 11 |

Odds ratios are multiplicative, so the geometric mean is the right average; an arithmetic mean would
be dominated by the largest pair.

`R12` **One pair is genuinely complementary.** Qwen3Guard 8B + ShieldGemma 2B has a conditional odds
ratio of **0.58 with a cluster interval of [0.38, 0.96]**, excluding 1 **from below** — after
conditioning on difficulty, one guard's miss makes the other's *less* likely. This is the only
negative association in the panel and the only pair in this study that beats independence rather than
falling short of it.

#### Where this converges with [LayeredEns], which Draft 1 missed entirely

**Their one surviving pair and our strongest surviving pair land on the same odds ratio.** Theirs:
probe₁₆ × probe₈, **CMH OR 158.7**. Ours: Qwen3Guard 4B + 8B, **CMH OR 158.00**.

⚠️ **The near-exact match is a coincidence and we say so.** Two studies on different corpora with
different members have no business agreeing to three digits, and nothing should be built on the
decimal. **The order of magnitude is the point, and so is what the two pairs have in common.** They
describe their survivor as sharing "an input representation and a training pipeline," and note this
"would suggest the taxonomy is coarser than the phenomenon." Ours are two scales of one model family
— the same kind of relation, arrived at from a different direction.

⚠️ **One asymmetry qualifies the convergence, and it runs against the neat version.** Conditioning
*strengthened* their pair — crude 68.0 rising to 158.7, which they note is "more than twice its crude
value" — while conditioning *weakened* every one of ours:

| within-family pair | crude OR | CMH OR | effect of conditioning |
|---|---|---|---|
| qwen3guard 4b+8b | 789.35 | 158.00 | ×0.20 |
| qwen3guard 06b+8b | 93.36 | 18.76 | ×0.20 |
| qwen3guard 06b+4b | 70.61 | 12.82 | ×0.18 |
| shieldgemma 2b+9b | 43.86 | 28.42 | ×0.65 |

**So item difficulty accounts for a substantial share of our within-family association and none of
theirs.** What converges is the *magnitude of the residual* and *which kind of relation leaves one*;
the direction of the conditioning effect does not. A reader should not take the two studies as
measuring the same quantity in the same regime, and we would rather state the asymmetry than let the
158 coincidence carry more weight than it can.

**The negative half converges too.** Their *other* same-row pair — perplexity × token-anomaly, same
dependency row but no shared training — **did not survive** (CMH OR 1.39, *p* = 0.907), which led
them to conclude that "same-row membership is therefore not sufficient on its own for correlated
failure that survives conditioning." **Our cross-family pairs behave identically**: all six guards are
the same *kind* of defense, and mere category membership buys them a geometric mean of 1.75.

**So both studies find the same thing, and Draft 1's framing was wrong.** Shared training
lineage survives conditioning on difficulty; shared defense *category* does not. **We are not
contradicting their §11.6 — we are supplying the sample size at which its positive half becomes
visible across more than one pair**, which is what they asked for.

### 5.6 Higher-order structure: not supported where testable

`R13` The pre-registration asked for a comparison against a pairwise-only prediction. We implement it
with the Kirkwood superposition approximation — **a choice the pre-registration did not fix, and
therefore post-hoc.**

| stack size | median measured | median independence | median Kirkwood | meas/Kirkwood | validity |
|---|---|---|---|---|---|
| 3 | 0.1891 | 0.0676 | 0.2399 | 0.86 | valid |
| 4 | 0.1746 | 0.0198 | 0.3981 | 0.42 | valid |
| 5 | 0.1680 | 0.0123 | **1.6006** | — | **void** |
| 6 | 0.1591 | 0.0031 | **7.3198** | — | **void** |

⚠️ **Kirkwood is unnormalized and is not a probability measure.** Under strong correlation it returns
values above 1. A "prediction" of 7.32 is not a small number to compare a measured rate against; it is
a broken instrument, and the tempting reading — *measured is 0.02× the pairwise prediction* — is
nonsense. **A validity gate voids those sizes before any reading.**

**Where the estimator is valid, measured joint failure is at or below the pairwise prediction.**
Higher-order structure predicts the opposite. **So the 51× penalty is pairwise correlation compounded,
not additional structure** — the more conservative reading, and the more useful one, since pairwise
correlation is estimable from any two guards a deployer already runs.

⚠️ **This is answered only at sizes 3 and 4.** The pre-registered comparison cannot be carried to the
full panel with this estimator and no other was pre-specified. **That is a limitation of our
pre-registration, not a result.**

### 5.7 Secondary: originals only

`R14` **18 of 150** unsafe originals are missed by all six guards. As pre-registered, this arm is
under-powered — most guards catch most originals — and is a consistency check rather than the primary.

## 6. What a deployer should take from this

**Do not multiply.** The multiplicative model is not a conservative approximation; it is optimistic
by a factor of 51 on this corpus. [LayeredEns] make the same point with different numbers, and two
independent measurements on different defense types now agree that the model fails.

**Prefer cross-publisher members over same-publisher scaling.** After conditioning on item
difficulty, within-family association averages **4× cross-family** on the normalized statistic (0.580
against 0.144). Adding a larger model from the same publisher buys close to nothing — Qwen3Guard 4B
and 8B have a conditional φ of 0.760, normalized 0.794, near the attainable maximum for their
marginals. Adding a guard from a different publisher buys more.

⚠️ **This is a mean difference, not a rule.** The groups overlap: one cross-family pair scores above
the weakest within-family pair (§5.5). **Cross-publisher selection is a better bet, not a guarantee of
independence**, and the highest cross-family raw penalty in our panel is still 1.97× — twice what
independence predicts.

⚠️ **And it does not transfer to substrate-sharing stacks.** [LayeredEns]'s central point is that where
members wrap one model, the shared failure point sits in something no member controls and member
diversity cannot reach it. Our finding concerns panels where no such substrate exists. A deployment
with both structures gets both terms, and only the second is purchasable.

**Budget the false-positive cost explicitly.** 6.7% against a best single member of 0.22% is a thirty-fold
increase. It is *cheaper* than independence predicts, which is a real consolation, but it is not small.

**Measure the assembled stack.** We agree with [LayeredEns] on this and our §5.4 sharpens why: the
penalty ratio a deployer cares about is marginal-dependent, so it cannot be read off a similarity
statistic, and a similarity statistic cannot be read off it.

## 7. Limitations

1. **The headline is a replication.** [LayeredEns] published it first and developed it further (§0).
2. ~~Our reading of [LayeredEns] is partial.~~ **Closed. Their §11 is now read in full, and it
   changed three things in this paper**: it supplied the φ_max bound we had denied existed (§5.4), it
   showed the family contrast is confounded with that bound (§5.5), and it revealed that their §11.6
   is underpowered by their own account — which retired Draft 1's claim that our result was the
   opposite of theirs. **Every correction ran against us**, which is the expected direction when a
   claim is checked against the source rather than a summary of it.
3. **H1's direction was not a blind prediction.** The panel data existed and its transfer result was
   known (pre-registration §0).
4. **The adversary is non-adaptive**, so all effects are lower bounds and we cannot speak to adaptive
   attack as [LayeredEns] can.
5. **The corpus is adversarially weighted.** Absolute FNRs are not deployment rates.
6. **One composition rule.** OR-composition only; nothing here tests AND, majority vote, or score-level
   fusion.
7. **Three families, one of them with three members.** The within-family evidence is four pairs drawn
   from two families, and three of those four share members. **The clean group separation is
   suggestive, not a law**, and a wider panel of publishers is the obvious next experiment.
8. **The difficulty control is unregistered** and was prompted by prior art found after the run (§5.5).
9. **The survival-count difference is still not fully attributable, though one confound is now
   removed.** §5.5b adopts their CMH estimator, so setting, sample size and label noise remain as
   differences and the statistic no longer does. **Their §11.6 is underpowered by their own
   statement**, so 8-of-15 against 1-of-15 remains consistent with sample size alone. The part that
   does *not* depend on the count is the convergence: same magnitude of odds ratio for the same kind
   of relation, in both studies. **The outstanding comparison is their stack measured on a corpus of
   our size**, which only they can run.
10. **Normalized φ is unstable where φ_max is small**, which is exactly the cross-family pairs whose
    near-zero association carries the deployment advice (§6).
11. **Higher-order structure is resolved only to size 4** (§5.6).
12. **Mechanism is inferred, not demonstrated.** That within-family pairs survive conditioning is
    consistent with shared training lineage; we did not manipulate lineage, and no member's training
    data is public enough to check.

## 8. Artifact

Per-item verdicts for all six guards on all 1,799 items; the frozen transformation specifications; the
pre-registration and its hash (`364800ff`); the analyzer, the pairwise-only supplement with its
validity gate, and the difficulty-stratification follow-up; the panel extension harness. Every
statistic in this paper is reproducible from the released verdicts with no GPU.

**Total new compute for this study: 7.9 GPU-minutes on A10G, $0.15.** Under OR-composition a stack
misses an item only when every member misses it, so the composition analysis is a re-analysis of
verdicts already collected. Only the two-model panel extension required inference.

## References

[LayeredEns] A. Alotaibi, M. S. Jabbar, S. Al-Azani, and M. Ahmed. *Layered LLM Defenses as an
Ensemble: Access Tiers, Inference Cost, and the Measured Failure Correlation Between Defense Layers.*
King Fahd University of Petroleum and Minerals; SDAIA-KFUPM Joint Research Center for Artificial
Intelligence. arXiv:2608.28327v1 [cs.CR], 28 August 2026. Preprint submitted to Elsevier, 58 pages.

[Kuncheva] L. I. Kuncheva and C. J. Whitaker. *Measures of Diversity in Classifier Ensembles and Their
Relationship with the Ensemble Accuracy.* Machine Learning 51(2), 2003. — cited via [LayeredEns] §4.3;
not read in the original for this draft.

[Biggio] B. Biggio, G. Fumera, and F. Roli. *Multiple Classifier Systems for Robust Classifier Design
in Adversarial Environments.* International Journal of Machine Learning and Cybernetics 1, 2010. —
cited via [LayeredEns] §4.3; not read in the original for this draft.

[T-03] V. Jha. *Measuring Guard Models: Asymmetry, Transfer, and the Instruments That Cannot See
Them.* Draft 4, 2026-08-31. — source of the corpus, the transformation set, and four of the six
per-item verdict sets.

---

### Production notes

- ~~Blocking: complete the read of [LayeredEns] §11.~~ **Done, and it forced Draft 2.** Three claims
  withdrawn: that φ carries no marginal ceiling, that the family groups do not overlap, and that our
  stratification result is the opposite of theirs.
- **[Kuncheva] and [Biggio] are still cited via the prior art rather than read** and remain marked as
  such. Either read them or drop them before submission; a via-citation must not pass as a read one.
- ~~Next experiment: re-run the stratification with their CMH estimator.~~ **Done (§5.5b), and it
  changed the paper's thesis from contrast to convergence.** Cost: nothing, a re-analysis of verdicts
  on disk.
- **The remaining comparison is theirs to run**: their seven-layer stack on a corpus the size of ours.
  We cannot supply it, and §7.9 says so.
- ~~Consider leading with the convergence rather than the substrate.~~ **Done.** The title now
  states the convergent finding and the subtitle the convergence. ⚠️ **Deliberately NOT titled on the
  158.7-versus-158.00 match**, which §5.5b calls a coincidence — a title resting on a number the paper
  disclaims would be the paper arguing with itself. The title rests on the substantive agreement
  instead: lineage survives conditioning, category does not, in both studies.
- Venue: **short measurement paper or workshop**, not a full track. The core thesis is [LayeredEns]'s.
  The honest pitch is "the extension they asked for, plus a setting their mechanism excludes."
- Anonymization for double-blind not yet performed.
