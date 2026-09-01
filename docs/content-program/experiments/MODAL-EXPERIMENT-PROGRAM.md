# Modal experiment program — what to run, why, and what it costs

**Written 2026-08-30, after the local E2 arm returned `1.00x [0.45, 4.20]`.**

Costs are quoted in **A100-80GB GPU-hours**, the unit that governs the bill. Multiply by the current
Modal rate, verified in the dashboard — do not trust a dollar figure written in this file. The
standing ceiling is **$100, no overages**, so this list is prioritized rather than exhaustive:
Tier 1 is what the papers need to survive review, Tier 2 is what makes them strong, Tier 3 is depth.

---

## The diagnosis this list responds to

| Result | Status | Weakness |
|---|---|---|
| E2 benign rephrasing | FPR 0.0333 → 0.0333, **1.00x [0.45, 4.20]** | Interval too wide to exclude 4x. n=150 yields 5 false positives. |
| E2 per-item instability | 4.0% (4B), 6.7% (0.6B) | Robust, being a within-item count — but two models is not a panel. |
| E3 context window | Clean null across a 16x range | Null only because **no corpus item reaches even 2048 tokens**. |

**The weakness is sample size and model breadth, not design.** Every Tier 1 item buys statistical
power or external validity on an experiment that is already specified and pre-registered.

---

# TIER 1 — required for the papers to survive review

## M1. E2 at full scale, multi-model panel
**Serves: T-03 (the headline result)**

**Question.** Does semantically-preserving rephrasing change guard verdicts, and by how much, with
intervals tight enough to state a number?

**Design.** The full WildGuardMix benign split (n around 5,000, not 150) x the five frozen
transformations x a cross-family panel. Same fail-closed scoring and seed discipline as the local arm.

**Panel** — the point is cross-family, not cross-size within one family:
Qwen3Guard-Gen 0.6B / 4B / 8B, Llama Guard 3 8B, Llama Guard 4 12B, ShieldGemma 2B / 9B,
WildGuard 7B, NeMo Guardrails.

**Why Modal.** 25,000 rephrasings x 9 models is 225,000 guard calls — weeks locally, and single-model.

**What it fixes.** A 33x larger benign base takes the interval from [0.45, 4.20] to roughly ±10%.
The headline stops being "we cannot tell" and becomes a number.

**Cost.** 12–18 GPU-hours.

---

## M2. The evasion arm at scale, with its adversarial ceiling
**Serves: T-03; the strongest standalone contribution in the program**

**Question.** How much unsafe content escapes detection under rewriting, and how far is generic
rewriting from an optimized attack?

**Design, two arms deliberately paired:**
- **Floor.** The frozen non-adversarial transformations (pre-registered, hash `cdc94f66`) applied to
  the full unsafe split. Reproducible by anyone; never optimized against a guard.
- **Ceiling.** A search that does optimize: best-of-n rephrasing with the guard's own verdict as the
  objective, capped at n=16 per item.

**Why the pair matters.** A floor alone understates the risk. A ceiling alone is unreproducible and
reads as an attack paper. Reporting both yields a **range with a defensible lower bound**, which is
what a venue will accept from a measurement paper.

**Cost.** 10 GPU-hours floor, 25 ceiling.

---

## M3. Quantization changes safety verdicts
**Serves: T-03; the most deployment-relevant claim available, and impossible locally**

**Question.** Does a guard served at Q4_K_M return the same verdicts as the same guard at Q8 and bf16?

**Design.** One corpus, one model, one seed, one context size. **Vary only weight precision:**
bf16 / fp16 / Q8_0 / Q5_K_M / Q4_K_M / Q4_0. Report **per-item verdict agreement**, not aggregate
rate — today's E2 arm is exactly the case where the aggregate rate was identical to four decimals
while 4 to 6.7 percent of individual verdicts moved.

**Why this is the strongest novel claim here.** Practitioners deploy quantized guards as a matter of
course; this program's entire local lane does. If Q4 and bf16 disagree on a non-trivial fraction of
items, **every published guard benchmark that does not state its quantization is under-specified** —
and almost none of them do. That is a finding about the field's measurement practice, which is
precisely T-03's thesis.

**Why Modal specifically.** bf16 for an 8B-plus guard does not fit the local 16 GB card. This
experiment is impossible locally, not merely slow.

**Cost.** 8 GPU-hours.

---

## M4. Long-context evasion — constructing the inputs E3 could not find
**Serves: T-03; converts a null into a finding**

**Question.** E3 measured zero effect of context size because nothing in the corpus reaches 2048
tokens. Does the effect appear when inputs are genuinely long?

**Design.** Construct inputs at 2k / 8k / 32k / 128k tokens by embedding a known-unsafe span in
benign filler, varying **position** (start / middle / end) independently of length. Measure detection
against both.

**Why it matters.** Agent transcripts and RAG contexts are long; guard benchmarks are short. If
detection degrades with length or position, every short-corpus benchmark systematically overestimates
deployed performance. This turns E3's null from "we found nothing" into "the instruments the field
uses cannot see this."

**Cost.** 10 GPU-hours.

---

# TIER 2 — makes the papers strong rather than merely sound

## M5. E1 concentration sweep
**Serves: T-03.** The current E1 tests one concentration (2x) of one category cluster; a null there
is thin. Sweep **1x / 2x / 4x / 8x** target density across **three** clusters — directed hostility,
criminal planning, regulated goods — both splits, 0.6B / 4B / 8B. If specialization pays anywhere,
this finds it; if nowhere, the null becomes a claim instead of a data point.
**Cost.** 20 GPU-hours, 48 adapters, parallel.

## M6. T-04's masking claim across the configuration space
**Serves: T-04, currently a single-configuration result.** T-04 argues that masking a field's loss
does not isolate it because LoRA shares weights — shown at one rank, one target-module set, one
family. Sweep **rank {4, 16, 64}** x **target modules {attention-only, attention+MLP}** x
**{Qwen, Llama, Gemma}**, with separate-adapters-per-field as the positive control. A reviewer will
ask whether the effect is an artifact of one configuration; this answers it first.
**Cost.** 18 GPU-hours.

## M7. Generator variance versus guard sensitivity
**Serves: T-03; a confound a good reviewer will raise.** Every rephrasing so far came from one
generator at one seed. Regenerate under **5 seeds x 3 generators** (Qwen3-14B, Llama-3.3-70B,
Mistral-Large) and decompose the variance. If most of it is generator-side, the guard-sensitivity
claim weakens and the paper must say so.
**Cost.** 12 GPU-hours.

## M8. Cross-guard evasion transfer
**Serves: T-03 and T-12.** Do rephrasings that evade guard A also evade guard B? A transfer matrix
over the M1 panel. **Why this reaches T-12:** defense-in-depth assumes independent failures. If
evasions transfer, stacking guards buys far less than the composition argument claims — a claim T-12
makes directly about layered containment.
**Cost.** 6 GPU-hours, reusing M2 artifacts.

---

# TIER 3 — depth if budget allows

- **M9. Calibration.** Are guard confidence scores meaningful? Reliability diagrams, ECE.
  Underexplored for guards specifically. 5 GPU-hours.
- **M10. Determinism audit.** How often does one guard flip on byte-identical input across backends,
  thread counts and batch sizes? Today's accidental n=1 control passed; a real audit puts a floor
  under every effect size in the program. 4 GPU-hours.
- **M11. Multilingual.** Does the rephrasing effect hold in Hindi, Arabic and Spanish? Directly
  serves the India and GCC markets. 10 GPU-hours.
- **M12. Category confusion.** Not safe/unsafe but which category is assigned, and where families
  systematically disagree. 6 GPU-hours.

---

# Recommended program

| | Items | GPU-hours | Buys |
|---|---|---|---|
| **Minimum viable** | M1, M3 | ~25 | A real number for the headline, plus the novel quantization result |
| **Strong paper** | + M2 floor, M4 | ~45 | Evasion lower bound and the long-context finding |
| **Full Tier 1+2** | + M2 ceiling, M5–M8 | ~130 | Removes every "one configuration" objection |

**Sequencing. Run M3 first** — cheapest, most novel, and impossible locally, so it validates the
Modal lane on something publishable rather than on plumbing. Then M1 for the headline, then M4,
then M2.

**Budget discipline.** Verify the current A100-80GB rate before launching. Depending on it,
"minimum viable" may be affordable while "full" is not. Every item is independently runnable and
independently publishable, so the program degrades gracefully instead of half-finishing.

**Data rule.** WildGuardMix and Aegis are public open corpora, satisfying the standing
open/synthetic/anonymized-only constraint for US cloud. No client or proprietary data enters this
program at any tier.
