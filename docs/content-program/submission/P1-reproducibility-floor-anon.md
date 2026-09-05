# How Reproducible Is a Guard Evaluation? A Measured Floor, and Where It Isn't Small

**Anonymous submission — under double-blind review**

> **Anonymization note.** Author, affiliation and the identity of companion submissions are
> withheld for double-blind review. Citations of the form `[Anon-*]` are unpublished companion
> work by the same authors and are anonymized accordingly; **all third-party citations are
> intact**. Pre-registration hashes are retained deliberately: they are this paper's evidence
> of pre-registration, and a SHA-256 identifies a frozen document rather than a person.
*Catalog ref: P1 · target: USENIX Security 2027 / IEEE S&P 2027*

> **Pre-registered before any measurement.** Hypotheses, arms, the acceptability comparison and the
> invalidation conditions were frozen and hashed (`5435ed47`) before the first run executed.
> **Two of the three hypotheses were refuted, including the one that motivated the paper.** Both
> refutations are reported in place.

---

## Abstract

Guard models are compared, ranked and selected on the basis of evaluation runs whose
*reproducibility has never been measured*. We ran the same guard, on the same corpus, at the same
quantization, seed, temperature and context size, eighteen times, and measured how often it returns
a different verdict.

**The floor is small: 998 of 1,000 items returned identical verdicts across eight independent runs**,
for a mean pairwise disagreement of **0.09%**; the Wilson 95% interval on the per-item instability
rate, 2 in 1,000, is [0.05%, 0.73%]. A between-run difference of several tenths of a percent on a
corpus like this one is therefore real, not noise; one below the interval's upper bound is not yet
distinguishable from the floor.

**That result refutes the hypothesis that motivated the experiment.** We predicted the floor would be
large enough to swallow effects routinely published as findings — specifically our own prior
measurement that `Q4_K_M` quantization changes 4 to 11 verdicts per thousand. It does not: those
effects sit 4–12× above the floor and survive. **We also refute the standard folk explanation** for
guard nondeterminism: varying thread count, which the serving stack's own documentation identifies
as the culprit, changes nothing measurable.

**Where the floor lives is more informative than its size.** The two unstable items do not flip
independently: across all eighteen runs, both flip together, in the same four runs, and every flip
crosses the model's own `Safe`/`Controversial` boundary — the undecided class of its three-valued
severity. Under the alternative policy setting that scores `Controversial` as safe, one of the two
would not count as a flip at all. The floor is a property of runs rather than of items, and it
lives in the boundary class.

**The paper's remaining contribution is a discrepancy we can localize but not yet resolve.** A prior
experiment observed **1.0% and 5.7%** verdict drift under the same nominal configuration — ten to
sixty times this floor. The two measurements differ in their *item population*: the high-drift sets
were composed entirely of items sitting at a decision boundary by construction, while the corpus here
is stratified and mostly not. **If the floor is population-dependent, then a single global floor is
the wrong object**, and the number that matters — the floor on borderline items, which is precisely
where effects are measured — remains unmeasured. We state this as an open hazard rather than
absorbing it into a headline, and we release the protocol and the estimator so that any guard
evaluation can report its own floor alongside its results.

**Keywords:** guard models, reproducibility, evaluation methodology, serving nondeterminism

---

## 1. Introduction

A guard model is a classifier deployed inline in an agentic pipeline, judging whether content is
safe. Guards are compared against one another constantly — in vendor documentation, in benchmark
tables, in procurement decisions — and those comparisons rest on evaluation runs.

**An evaluation run is a measurement, and measurements have noise.** For guard evaluation, the
magnitude of that noise has, to our reading, never been reported. Papers state the model, usually the
corpus, sometimes the temperature and seed. They do not state, because nobody has measured, how much
the same evaluation would move if simply run again.

This matters because the effects being reported are often small. A guard comparison that finds one
model two points better than another is making a claim about a difference; if two runs of the *same*
model differ by two points, the claim is empty. The question is not rhetorical — it is arithmetic,
and it has an answer.

### 1.1 What we expected, and what we found

We pre-registered three hypotheses. **Two were refuted.**

| | hypothesis | outcome |
|---|---|---|
| **H1** | Agreement between two runs at identical configuration is below 1.0 | **supported**, but barely |
| **H2** | The drift is attributable to thread count | **refuted** |
| **H3** | The floor is large enough to swallow effects published as findings | **refuted** |

H3 was the paper's motivation. We expected to be able to say that a share of published guard
comparisons report differences smaller than their own measurement noise. **The data does not support
that claim, and we do not make it.**

### 1.2 Contributions

1. **The first measurement, to our knowledge, of guard-evaluation reproducibility**: 998/1,000 items
   unanimous across eight independent runs, 0.09% mean pairwise disagreement (§4) — and, from the
   per-item record, that the two unstable items flip together, in the same runs, at the
   `Safe`/`Controversial` boundary (§4.2).
2. **A refutation of the standard explanation.** Thread count, which the serving stack's own
   determinism note identifies as the source of nondeterminism, explains none of the observed drift
   (§4.3).
3. **A localized open hazard.** A 10–60× discrepancy against a prior measurement, attributable to
   item population, which implies the floor is not a single number (§5).
4. **A protocol and estimator** that lets any guard evaluation report its own floor for the cost of
   one additional run (§6).

---

## 2. Related work and positioning

**Nondeterminism in LLM serving** is documented at the systems level: batching, kernel selection,
reduction order and thread count can all change floating-point results, and quantized inference
compounds this. That literature establishes that variation *can* occur. It does not measure what it
costs a downstream safety decision, which is the gap here.

**Guard model evaluation** is largely benchmark-aggregate. In the guard-evaluation papers we examined
([WildGuard], [GuardBench]) it reports model, corpus and metric, and does not report serving
configuration beyond the model tag, does not repeat runs, and does not state a noise floor. We are not aware of prior work that measures repeated-run agreement for
guard classifiers specifically.

**Guard-model instability under perturbation** is established [GuardMeaning], including the
observation that flips concentrate in the ambiguous score region. That work perturbs the *input*;
we hold the input fixed and perturb nothing at all, which is the complementary measurement and, to
our reading, unreported.

**Reproducibility work in ML** has concentrated on training reproducibility — seeds, data order,
hardware. Inference-time reproducibility of a *fixed* checkpoint has received far less attention,
presumably because it is assumed to be exact. For quantized guards served through llama.cpp, it is
not exact, and §4 measures by how much.

**Scope of the prior-art check.** The claim above that we found no prior measurement of
repeated-run verdict agreement for guard classifiers rests on a keyword search of the
guard-evaluation and quantization literature conducted on 2026-08-31, **after** this experiment
ran. It is not a systematic survey. The systems literature on serving nondeterminism is substantial
and we do not claim novelty on the existence of the phenomenon — only on measuring its magnitude
for a safety decision, and on the population-dependence hazard in §5.

**What we do not claim.** We do not claim guard evaluations are unreliable — the measured floor says
the opposite for the population we tested. We do not claim novelty on the existence of serving
nondeterminism. Our contribution is its magnitude, its non-attribution to the standard cause, and
the population-dependence hazard in §5.

---

## 3. Method

### 3.1 Design

**One model, one corpus, one nominal configuration, repeated.** Qwen3Guard-Gen-4B at `Q4_K_M`, 1,000
items stratified on the harm label from a public corpus, `num_ctx` 8192, seed 0, temperature 0,
fail-closed scoring. Three arms:

| arm | runs | what varies | isolates |
|---|---|---|---|
| **A** | 8 | **nothing declared**; separate containers | the floor a practitioner hits without changing anything |
| **B** | 6 | `num_thread` ∈ {2, 4, 8}, two runs each | whether thread count explains drift |
| **C** | 4 | A10G and L4, two runs each | whether GPU type contributes |

**Arm A is the headline, and its design principle is that nothing varies.** Everything a practitioner
would think to report — model, quantization, corpus, seed, temperature, context size — is fixed and
identical. The drift measured is the drift nobody controls for.

**Serving stack.** Ollama over llama.cpp, the `Q4_K_M` GGUF from a public conversion, one
container per run on a serverless GPU provider. The run records carry the model tag, `num_ctx`,
seed, thread setting, and per-item raw output; **they do not carry the Ollama or llama.cpp
version**, and it was not pinned. §6 asks every evaluation to report the stack version. This one
cannot, and the omission is stated rather than repaired after the fact.

### 3.2 Scoring

Unparseable output is scored harmful (fail-closed); fail-open would let a broken decoder report
perfect recall. **Unparsed rate is reported per run before any agreement figure**, and a run above 5%
is excluded as a generation failure rather than reported with a caveat. No run was excluded: **zero
unparsed outputs across all 18,000 evaluations.**

### 3.3 The statistic, and an honest caveat about it

The primary quantity is **mean pairwise per-item verdict agreement** over all 28 pairs drawn from
arm A's 8 runs.

⚠️ **Those 28 pairs are not independent.** They are drawn from a shared set of eight runs, so a
naive confidence interval on the mean understates uncertainty. We therefore lead with a statistic
that does not have this problem: **the count of items returning identical verdicts across all eight
runs simultaneously**, which is a single count over 1,000 independent items.

---

## 4. Results

### 4.1 The floor

**998 of 1,000 items returned identical verdicts across all eight runs.**

| | |
|---|---|
| Mean pairwise agreement (28 pairs) | **0.9991** |
| Worst pair | 0.9980 |
| Best pair | **1.0000** |
| Items ever disagreeing | **2 / 1,000** — Wilson 95% [0.05%, 0.73%] |
| Mean pairwise disagreement | **0.09%** = 0.9 verdicts per 1,000 |

At least one pair of runs was **exactly identical** across all 1,000 items, which bounds the effect
from below in a way an average cannot: perfect reproducibility is achievable, just not guaranteed.

### 4.2 The disagreement is concentrated, not scattered

The two disagreeing items were not different items in different pairs. **Each disagreed in 12 of the
28 pairs**, while the remaining 998 were unanimous everywhere. Twelve disagreeing pairs is the
signature of a two-against-six split: each item returned its minority verdict in **two of the
eight runs**, not in half of them.

This distinction is not cosmetic. A floor of 0.09% spread thinly across nine hundred items would
imply pervasive low-level instability. **A floor of 0.09% concentrated in two items implies a small
set of genuinely borderline inputs and a stable remainder** — and it is the second, which is why
§5's population argument follows.

**The two items flip together, and the unit of instability is the run.** Reading the per-item
verdicts rather than the summary statistics shows three things the counts above do not:

| | item `m0489` (labeled benign) | item `m0749` (labeled harmful) |
|---|---|---|
| majority verdict, 6 of 8 runs | `Safe`, no category | `Controversial`, *Unethical Acts* — scored harmful |
| minority verdict, 2 of 8 runs | `Controversial`, *Jailbreak* — scored harmful | `Safe`, no category |
| runs returning the minority verdict | A3, A7 | **A3, A7** |

1. **Both items flip in the same two runs.** Runs A3 and A7 differ from the other six on both
   items, and no run differs on only one. Across all eighteen runs in the experiment — arms B and
   C included — the same two items are the only unstable ones; they flip in four runs (A3, A7, one
   `num_thread=8` run and one L4 run), and they always flip together. Every run falls into one of
   two states, fourteen in one and four in the other. That is the signature of a run-level
   property — something about the container a run landed in — not of two items each drawing an
   independent coin.
2. **Every flip crosses the `Safe`/`Controversial` boundary.** Qwen3Guard emits a three-valued
   severity; `Controversial` is the model's own undecided class, and the harness scores it harmful.
   Neither item ever moves between `Safe` and `Unsafe`. The whole measured floor is a property of
   the boundary class.
3. **One of the two flips is a category flip as much as a severity flip.** `m0489`'s minority
   verdict carries the *Jailbreak* category, which the harness gates as harmful regardless of
   severity. Under the alternative policy that scores `Controversial` as safe, `m0489` would still
   count as a flip and `m0749` would not: the floor would be one item in a thousand, and *which*
   item is unstable would depend on a policy setting rather than on the model.

The two-state structure is not explained by anything the design varied. The four minority-state
runs include a cold-cache run and three warm-cache runs, an unpinned and a pinned thread count, and
one of two L4 runs whose sibling on identical hardware stayed in the majority state.

### 4.3 Thread count explains nothing (H2 refuted)

| | agreement |
|---|---|
| Arm B, same thread count | 0.9993 |
| Arm B, across thread counts | **0.9993** |

Identical to four decimal places. The serving stack's own determinism note states that a quantized
build is deterministic for a fixed model file, context size **and thread count**, implying thread
count is the loose variable. **On this evidence it is not**, and practitioners pinning thread count
in the belief that it buys reproducibility are pinning the wrong thing.

### 4.4 Hardware contributes nothing measurable

| | agreement |
|---|---|
| Within A10G | 1.0000 |
| Within L4 | 0.9980 |
| Across A10G vs L4 | 0.9990 |

Cross-hardware agreement (0.9990) is indistinguishable from within-hardware agreement (mean 0.9990).
**Two different GPU architectures produce the same verdicts as one architecture produces on repeat.**

In both arms the only disagreeing items are the same two as in arm A, and in each arm exactly one
run — the second `num_thread=8` run, and the second L4 run — sits in the minority state of §4.2.
Thread count and GPU type do not create instability of their own; they inherit the same two-state
behavior at the same two items.

### 4.5 H3 refuted: the floor does not swallow published effects

The comparison target was fixed in advance: our own prior finding that `Q4_K_M` quantization changes
**4 to 11 verdicts per thousand** relative to an `f16` reference.

**Those effects are 4–12× the floor.** They survive. Fixing the target before measuring is what makes
this a refutation rather than a rationalization — had the floor come out at 5 per thousand, we would
have been obliged to report those findings as inside their own noise.

---

## 5. The discrepancy, which is the paper's most useful contribution

### 5.1 A 10–60× gap

A prior experiment in the same program re-scored two item sets under the same nominal configuration
on different containers and observed:

| set | items | drift |
|---|---|---|
| Qwen3Guard-4B evaded set | 97 | **1.0%** |
| Qwen3Guard-0.6B evaded set | 105 | **5.7%** |

Against this paper's **0.09%**. Same model family, same quantization, same seed, same temperature,
same serving stack. **The measurements disagree by an order of magnitude or two, and averaging them
would be the wrong response.**

### 5.2 The populations differ, and differ in a way that predicts the gap

The high-drift sets were **not** stratified samples. Every item in them was selected by a two-step
filter: it was **caught** by the guard in its original form, and then **missed** after a
semantically-preserving rephrasing.

**That filter selects for proximity to a decision boundary.** An item that flips under a small input
perturbation is, by construction, one the model was nearly undecided about. The corpus used in this
paper is stratified on the harm label and makes no such selection — most of its items are not close
to any boundary, which §4.2 confirms directly: 998 of them never move at all.

### 5.3 The consequence: a global floor may be the wrong object

If reproducibility depends on item difficulty, then:

- **0.09% is the floor for a stratified corpus** and is the right number for a benchmark reporting
  aggregate performance over one.
- **It is the wrong number for an effect measured on borderline items** — which is where
  perturbation studies, adversarial evaluations and fine-grained comparisons concentrate by design.
- **The floor that matters most is the one we did not measure.**

**Independent support from prior work.** Pinneri and Louizos [GuardMeaning] report paraphrase-induced
label flips **highest in the ambiguous score region (0.25–0.75)** and lowest at the confident
extremes. That is the same shape our hypothesis predicts, arrived at from a different direction:
instability concentrates where the model is undecided. It does not measure a reproducibility floor,
but it makes the population-dependence hypothesis considerably more plausible than our two unstable
items alone would.

**A second measurement on a second corpus.** A companion study [Anon-F] repeated the eight-replicate
protocol with the same model and quantization on its own 1,000-item, adversarially weighted corpus
and found 0.107% mean pairwise disagreement with, again, exactly two items ever unstable. Two
corpora, two floors within 0.02 percentage points of each other, two unstable items each — and in
this paper's data both sit at the `Safe`/`Controversial` boundary (§4.2). The population hypothesis
is therefore sharper than "borderline items": the floor appears to live in the model's own undecided
class, and a corpus's floor is a function of how many of its items the model files there.

⚠️ **This is still a hypothesis, not a result.** We did not run arm A on a borderline-enriched set. Doing
so requires only repeating the protocol on such a set and is the immediate follow-up. We state it as
an open hazard because the alternative — quoting 0.09% as a universal floor — would be exactly the
overreach this paper was written to guard against.

### 5.4 What this means for the companion studies

Applying the finding honestly to results from the companion studies:

- **Quantization effects (4–11 per 1,000) survive**, at 4–12× the stratified-corpus floor (§4.5).
- **Paired within-run comparisons are unaffected.** The floor is a **between-run** quantity. A
  McNemar test on discordant pairs within a single run does not inherit it, and conflating the two
  would understate and overstate different findings simultaneously. The pre-registration forbids
  blurring this in either direction.
- **Any between-run difference below ~0.1% on a stratified corpus is not reportable**, and any such
  difference on a borderline-enriched set is currently **unbounded** by evidence.
- **The floor is partly a policy artifact.** Both unstable verdicts are `Controversial` verdicts, and
  the harness's `controversial_is_harmful` setting decides whether one of them counts (§4.2). A
  companion paper [Anon-G] shows that fine-tuned guards in the same program lose the `Controversial`
  class altogether; on such a model this floor would be zero and the setting inoperative. A reported
  floor should state the severity policy it was scored under.

---

## 6. A protocol worth adopting

The floor is cheap to measure and currently nobody reports it.

**Minimum viable protocol, one extra run:**

1. Run your evaluation **twice**, at identical configuration, in separate processes or containers.
2. Report **per-item agreement** between the two runs alongside your headline metric.
3. **Refuse to claim any between-run difference smaller than the disagreement you just measured.**

**Better, eight runs:** report the count of items unanimous across all runs, and the identity of the
items that are not. That set is diagnostically useful on its own — it is a list of the inputs your
guard is genuinely undecided about.

**What to report:** serving stack and version, quantization, `num_ctx`, seed, temperature,
**thread count** (even though §4.3 shows it does not matter here — that is a finding about one
stack, and the next stack may differ), and the measured floor.

**What not to bother pinning:** on this evidence, thread count and GPU architecture. Pinning them is
harmless and cheap, but it should not be mistaken for having addressed reproducibility.

---

## 7. Threats to validity

**One model, one quantization, one serving stack.** Qwen3Guard-4B at `Q4_K_M` through
Ollama/llama.cpp. A floor that varies by stack is itself a finding and is untested here. vLLM and
transformers, with different batching and kernel-selection behavior, may differ substantially.

**The population limitation is the paper's own headline hazard** (§5) and is not mitigated elsewhere.

**Eight runs is a small sample for a rare event.** With 2 disagreeing items, the estimate of *which*
items are unstable is far less precise than the estimate of *how many*. A larger repetition count
would sharpen the disagreement set without much changing the rate.

**Non-independent pairs.** §3.3. We lead with the unanimity count for this reason, and report the
pairwise mean as a secondary figure.

**Container assignment is not controlled.** Arm A's runs landed on whatever hardware the scheduler
provided. Arm C suggests hardware does not matter, but arm A is not a controlled test of that.

**The two unstable items were inspected at the verdict level, not the text level.** Both are
`Controversial`-boundary verdicts (§4.2), which is the borderline signature §5 predicts, and the
corpus is access-gated so their text is not reproduced here. A malformed-text explanation would
have to account for both items flipping in the same runs, which it does not.

**Eight runs is also a small sample of run states.** Four of eighteen runs sat in the minority state
(Wilson 95% [9%, 45%]); the rate at which a fresh container lands there is not well estimated, and
nothing in the run records identifies what differs about those four.

---

## 8. Conclusion

We measured how much a guard evaluation moves when you simply run it again. On a stratified corpus
the answer is: **very little.** 998 of 1,000 items are unanimous across eight independent runs, the
mean pairwise disagreement is 0.09%, and at least one pair of runs is exactly identical.

That is good news, and it refutes the claim this paper set out to make. It also refutes the standard
explanation for guard nondeterminism: thread count, the variable the serving documentation
implicates, explains none of the observed drift, and neither does GPU architecture.

**What survives is narrower and more useful than the claim we expected to make.** The disagreement
is concentrated in two items rather than spread across the corpus — two items that flip together,
in the same runs, at the model's own `Safe`/`Controversial` boundary — and a prior measurement on
a set composed *entirely* of borderline items showed drift ten to sixty times higher. If reproducibility tracks item difficulty, the floor is not one number, and the number that
matters most — the floor where effects are actually measured — is still unmeasured.

Reporting a floor costs one extra run. Until it becomes normal to report one, the field is comparing
guards without knowing what a difference is worth.

**Open work:** the borderline-item floor (§5.3); cross-stack floors for vLLM and transformers; the
run-level state that moves both items at once, which is a container-level cause rather than an
item-level one (§4.2); and whether the floor scales with model size, since the prior 0.6B
observation was five times the 4B's.

---

## Artifact

Per-item verdicts for all 18 runs, including the raw two-line output behind every verdict; the
pre-registration and its hash; the corpus row indices; the estimator implementing §6; and the
script that recomputes every figure in §4 from the run files, including the two-state structure of
§4.2. Source corpus is public but access-gated, so item indices are published rather than item
text, with a rebuild script.

---

## References

[WildGuard] *WildGuard: Open One-Stop Moderation Tools for Safety Risks, Jailbreaks, and Refusals of
LLMs.* University of Washington, Allen Institute for AI, Seoul National University.
arXiv:2406.18495, 2024. — source of the evaluation corpus.

[GuardMeaning] C. Pinneri and C. Louizos. *Guarding the Meaning: Self-Supervised Training for
Semantic Robustness in Guard Models.* Qualcomm AI Research. arXiv:2511.10665, 2025. — establishes
that guard verdicts move under meaning-preserving paraphrase; this paper measures how much they move
when *nothing* changes, which is the complementary quantity.

[GuardBench] *Benchmarking Open-Source Safety Guard Models: A Comprehensive Evaluation.*
arXiv:2605.28830, 2026. — an example of the comparison genre whose noise floor is unreported.

[QuantTemp] *The Joint Effect of Quantization and Sampling Temperature on LLM Safety Alignment: A
Factorial Analysis.* arXiv:2606.29581, 2026. — varies serving parameters deliberately; we hold them
fixed and measure the residual.

[Anon-F] Anonymous. *Companion preprint; title withheld for review.* 2026.

[Anon-G] Anonymous. *Companion preprint; title withheld for review.* 2026.
