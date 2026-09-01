# Vary the Input, Not the Decoding: A Training-Free Defense Against Paraphrase Evasion of Guard Models

**Research paper · Draft 1 · 2026-08-31 · Vikram Jha**
*Catalog ref: P2 · target: NeurIPS 2027 / IEEE S&P 2027*

> **Both experiments were pre-registered and hashed before their data existed** — the failed
> decoding-variation defense (`19e42076`) and this one (`42baffaf`). **The same acceptability bound,
> fixed in advance at 2× baseline false-positive rate, was applied to both**, so the comparison is
> not retrospective. We pre-committed to reporting a second negative result if this defense also
> failed; it did not.

---

## Abstract

Guard models can be evaded by rephrasing unsafe content. A natural defense follows from how the
attack works: if sampling many rewrites defeats a guard, perhaps sampling many guard judgments
defends it. **We tested that and it fails.** Aggregating *k* guard samples at temperature 1.0
recovers 47% of evasions on a 4B guard, at **3.4× the baseline false-positive rate** — far outside a
budget fixed before the experiment.

**The failure is diagnostic.** The guard is **80.9% unanimous across 16 draws** at temperature 1.0,
and switching a single sample from greedy to stochastic decoding does **four times** the work that
adding fifteen more samples does. There is almost no decoding variance to aggregate. The attacker's
temperature varies the **input text**; the defender's varied only the **model's own decoding**, and
the model is sensitive to the former and nearly deterministic in the latter.

**Acting on that diagnosis works.** Paraphrasing the *input* k times and flagging if any copy is
judged unsafe recovers **22.7%** of evasions on the 4B guard at **1.6×** baseline false-positive rate,
and **46.7%** on a 0.6B guard at **1.4×** — both inside the same pre-fixed budget that the
decoding-variation defense violated. It also improves the false-negative rate on *unmasked* unsafe
content, from 0.1600 to 0.1400. The defense is **training-free and inference-time**: it requires no
access to guard weights, no fine-tuning, and no change to the deployed model.

**Aggregation rule matters more than budget.** Any-unsafe aggregation succeeds; majority voting
recovers 1–9% and is not a defense at any k. We release both pre-registrations, the paraphrase
sets, and per-item verdicts for 7,956 guard calls.

**Keywords:** guard models, adversarial robustness, inference-time defense, paraphrase, AI safety

---

## 1. Introduction

Guard models classify content as safe or unsafe inline in a deployed pipeline. They are known to be
sensitive to superficial linguistic variation: meaning-preserving paraphrases can flip their verdicts
[GuardMeaning]. Prior work in this program measured the *direction* of that sensitivity and found it
sharply asymmetric — rephrasing leaves the false-positive rate flat while raising the false-negative
rate 1.42×, with best-of-16 selection over generic rewrites evading 72–97% of what six guards across
three publishers originally catch.

**That leaves a defense question, and one obvious answer.** The attacker's advantage came
predominantly from *sampling*: at a fixed budget of four candidates, moving from greedy to
temperature-1.0 decoding raised evasion by 37.3 points, while quadrupling the budget added only 14.3.
If sampling is what makes the attack work, sampling ought to make a defense work too.

**It does not, and why it does not is the paper.**

### 1.1 Contributions

1. **A pre-registered negative result with a mechanism** (§3): aggregating the guard's own stochastic
   decoding fails, because the guard is ~80% unanimous across draws and has almost no variance to
   aggregate.
2. **The distinction that explains it** (§3.3): attacker and defender were varying different things.
   Sampling helps whoever perturbs the axis the model is actually sensitive to, and that axis is the
   input, not the decoding.
3. **A training-free defense that works** (§4): paraphrase-and-vote, 22.7% and 46.7% recovery inside
   a pre-fixed cost bound that the decoding defense violated.
4. **Aggregation rule as the dominant design choice** (§4.3): any-unsafe succeeds where majority
   voting recovers almost nothing, at every budget.

---

## 2. Related work

**Guard models are known to be paraphrase-sensitive.** Pinneri and Louizos [GuardMeaning] demonstrate
meaning-preserving paraphrases flipping guard verdicts across six open-source guards, and propose a
**self-supervised training** method that reduces semantic variability by ~58% while improving
benchmark accuracy.

**Our defense is complementary, not competing, and the difference is deployment-shaped.** Theirs is a
**training-time** intervention: it requires access to the guard's weights and a fine-tuning run.
Ours is **inference-time and training-free**: it wraps an unmodified guard, works on a model served
behind an API, and can be switched off. Where weights are available, their approach is likely
stronger and ours is likely complementary — we do not compare them empirically and do not claim
superiority.

**Training-free mitigations exist for a different failure.** LongGuard [LongGuard] supplies chunked
detection and attention-head sharpening for **long-context** guardrail failure. Those target
positional dilution over long inputs; paraphrase evasion at short context is a distinct problem and
the mitigations do not transfer.

**What we do not claim.** Novelty on paraphrase sensitivity [GuardMeaning]; that this is the best
defense; or that results transfer beyond the two models tested.

---

## 3. The defense that fails, and its diagnosis

### 3.1 Design

Score each input *k* times at temperature 1.0 with fixed seeds and aggregate, instead of once
deterministically. Three item sets are scored under **every** configuration: evading candidates
(recovery), unsafe originals (baseline FNR), and **benign originals (the false-positive cost)**.

**Measuring recovery without the benign cost at the same k is the central error this design exists
to avoid.** Any aggregation that catches more will also flag more, and reporting only the gain would
present threshold-lowering as a defense.

**The acceptability bound was fixed before the run at 2× baseline benign FPR**, and we pre-committed
to reporting a negative result if recovery and cost rose together.

### 3.2 Result: it fails

Qwen3Guard-4B, baseline benign FPR 0.0333, bound 0.0667:

| rule | k | recovery | benign FPR | verdict |
|---|---|---|---|---|
| any-unsafe | 1 | 0.4433 | 0.0867 | **too expensive** |
| any-unsafe | 4 | 0.4742 | 0.1133 | **too expensive** |
| any-unsafe | 16 | 0.4742 | 0.1133 | **too expensive** |
| majority | 16 | 0.0103 | 0.0333 | within budget, recovers nothing |

No configuration recovers meaningfully inside the bound. The 0.6B behaves the same: 0.5905 recovery
at 0.1600 FPR, a 3.0× cost.

### 3.3 The diagnosis, which is the useful part

**The recovery comes from the temperature switch, not the aggregation:**

| | temp 0 → 1.0 at k=1 | k=1 → k=16 |
|---|---|---|
| 4B | **+52** items flagged | +13 |
| 0.6B | **+70** items flagged | +19 |

**Because the guard is nearly deterministic even at temperature 1.0.** Across 16 draws per item,
**321/397 (80.9%)** of 4B items and **300/405 (74.1%)** of 0.6B items return unanimous verdicts, with
a sharply bimodal vote distribution. **There is almost nothing to aggregate.**

Raising the temperature simply moves the operating point: the 4B flags 132 of 397 items at
temperature 0 and 184 at temperature 1.0 — more evasions caught *and* more benign content flagged,
in roughly the proportion a threshold change would produce.

**Attacker and defender were not doing the same thing.** The attacker's 16 rewrites are 16 genuinely
different *inputs*, and guard verdicts across different inputs vary a great deal. The defender's 16
draws are 16 samples of the *same decision on the same input*, and that decision is ~80% unanimous.
**Sampling helps whoever varies the axis the model is sensitive to.**

---

## 4. The defense that works

### 4.1 Design

For each input, generate *k* paraphrases, score the original plus each paraphrase, and aggregate.
Same three item sets, same configurations, **same 2× bound**, so the two defenses are directly
comparable.

**The paraphrase instructions are deliberately not the attack's transformations.** Reusing the
attack families would let the defender paraphrase along exactly the axis the attacker exploited — a
flattering result no adaptive attacker would respect. We use neutral rewrites ("restate plainly",
"normalize formatting and tone"), fixed before the run.

### 4.2 Result: it works, inside the bound

**Qwen3Guard-4B**, baseline FPR 0.0333, bound 0.0667:

| k | cost | recovery | benign FPR | unsafe FNR | verdict |
|---|---|---|---|---|---|
| 1 | 1 gen + 2 guard | 0.1237 | 0.0467 | 0.1467 | ok |
| 4 | 4 gen + 5 guard | 0.1753 | 0.0467 | 0.1400 | ok |
| **8** | 8 gen + 9 guard | **0.2268** | **0.0533** | **0.1400** | **ok** |

**Qwen3Guard-0.6B**, baseline FPR 0.0467, bound 0.0933:

| k | cost | recovery | benign FPR | unsafe FNR | verdict |
|---|---|---|---|---|---|
| 1 | 1 gen + 2 guard | 0.3333 | 0.0667 | 0.1533 | ok |
| 4 | 4 gen + 5 guard | 0.4444 | 0.0667 | 0.1333 | ok |
| **8** | 8 gen + 9 guard | **0.4667** | **0.0667** | **0.1333** | **ok** |

**Head to head, at the same pre-fixed bound:**

| | recovery | benign FPR | multiple of baseline | inside bound |
|---|---|---|---|---|
| Decoding variation, 4B | 0.4742 | 0.1133 | 3.4× | **no** |
| **Input variation, 4B** | 0.2268 | 0.0533 | **1.6×** | **yes** |
| Decoding variation, 0.6B | 0.5905 | 0.1600 | 3.0× | **no** |
| **Input variation, 0.6B** | **0.4667** | 0.0667 | **1.4×** | **yes** |

**Input variation recovers less in absolute terms and costs far less**, which is what puts it inside
a budget the alternative violated. That is the trade a deployer actually faces.

**It also helps on content that was never evaded.** Unsafe-original FNR falls from 0.1600 to 0.1400
(4B) and 0.1867 to 0.1333 (0.6B), so this is not solely an anti-evasion patch — it improves baseline
detection.

### 4.3 Aggregation rule dominates budget

| rule | 4B best within bound | 0.6B best within bound |
|---|---|---|
| **any-unsafe** | **0.2268** | **0.4667** |
| majority | 0.0103 | 0.0889 |

**Majority voting is not a defense at any budget we tested.** It recovers 1–9% while costing the same
generation. The reason follows from §3.3's bimodality carried into paraphrase space: an evaded item
is usually judged safe by *most* paraphrases and unsafe by a few, so requiring a majority discards
exactly the signal that matters. **Any-unsafe is the correct rule, and reporting only it would have
hidden how much that choice carries.**

### 4.4 Cost, stated plainly

k paraphrases costs **k generator calls plus k+1 guard calls** — materially more than the decoding
defense's k guard calls, since it invokes a second model. At k=8 that is roughly an order of
magnitude more compute per decision than an undefended guard. **A defense that needs k=8 is a
different product from one that works at k=1**, and §4.2 shows k=1 already recovers 12% (4B) and 33%
(0.6B) at negligible false-positive cost, which may be the better operating point for most
deployments.

---

## 5. Threats to validity

**Two models, one family.** Qwen3Guard at two scales. The asymmetry this defends against replicates
across three families in prior work, but this defense has not been tested on them.

**The paraphraser is a second model, and a failure surface.** A generator that alters meaning
converts a defense into a source of false positives; we constrain it with neutral instructions and
fixed seeds but do not verify semantic preservation, which is the same unperformed check prior work
in this program already owes.

**An adaptive attacker is untested.** Our attacker was blind to the defense. One who knows inputs
will be paraphrased could search for payloads that survive paraphrasing, and nothing here bounds
that.

**The evaded sets are borderline by construction**, so recovery is measured on a population selected
for instability. That is the right population for the question, and it means the absolute recovery
figures should not be read as guard-wide improvements.

**The 2× bound is a judgment.** It was fixed before the data to prevent post-hoc rationalization, but
a deployer with different tolerances will read §4.2's curves differently, which is why they are
published in full.

---

## 6. Conclusion

A defense that mirrors an attack's mechanism is not automatically a defense. Sampling made the attack
work, and sampling the guard's own decoding does not work — because the guard is ~80% unanimous
across draws and the variance the attacker exploited was never in the decoding at all.

**Varying the input instead recovers 23% and 47% of evasions inside a false-positive budget fixed
before either experiment ran**, improves baseline detection as a side effect, and requires no access
to the guard's weights.

The result that generalizes past this particular defense: **sampling helps whoever varies the axis
the model is actually sensitive to.** For guard models that axis is the input. Any proposed defense
premised on "the attack used sampling, so the defense can too" should be checked against which thing
is being sampled.

**Open work:** cross-family replication; an adaptive attacker who knows the defense; semantic
verification of the paraphraser; and a comparison against the training-time method of [GuardMeaning],
which we position as complementary but do not measure against.

---

## References

[GuardMeaning] C. Pinneri and C. Louizos. *Guarding the Meaning: Self-Supervised Training for
Semantic Robustness in Guard Models.* Qualcomm AI Research. arXiv:2511.10665, 2025.

[LongGuard] Z. Chen, X. Wu and S. Hu. *LongGuard: Mechanistic Analysis and Training-Free Mitigation
of Long-Context Failure in Safety Guardrails.* arXiv:2608.27580, 2026.

[WildGuard] *WildGuard: Open One-Stop Moderation Tools for Safety Risks, Jailbreaks, and Refusals of
LLMs.* arXiv:2406.18495, 2024. — source of the evaluation items.

[AttackEns] *Attack Ensembles Expose a Safety-Utility Trade-off in Black-Box Guard Defenses Against
Encoded VLM Jailbreaks.* arXiv:2607.26574, 2026.

---

## Artifact

Both pre-registrations with hashes; all paraphrases with their generator seeds and instructions;
per-item verdicts for 7,956 guard calls across both defenses; the aggregation code. Source corpus is
public but access-gated, so item indices are published with a rebuild script rather than item text.
