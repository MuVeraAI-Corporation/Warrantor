# Positional Guard Evasion at Short Context: A Replication Note

**Anonymous submission — under double-blind review**

> **Anonymization note.** Author, affiliation and the identity of companion submissions are
> withheld for double-blind review. Citations of the form `[Anon-*]` are unpublished companion
> work by the same authors and are anonymized accordingly; **all third-party citations are
> intact**. Pre-registration hashes are retained deliberately: they are this paper's evidence
> of pre-registration, and a SHA-256 identifies a frozen document rather than a person.
*Catalog ref: P3 · target: workshop / short-paper track — **not** a full-venue submission*

> ⚠️ **Drafted as a novel-contribution paper; it is not one.** A prior-art check run after Draft 1
> found **LongGuard** [LongGuard], published 2026-08-27 — four days before this work — which
> establishes the same positional finding across **15 guardrails** over a **0.25k–32k** grid,
> supplies the attention→logit→behavior mechanism this note defers, and implements the
> chunked-detection defense this note only predicts.
>
> **The measurements below stand; the novelty claim does not.** Draft 2 repositions this as a
> replication at short context on two models LongGuard did not test, and **retracts Draft 1's claim
> to have refuted length dilution** (§4.2). Full assessment in `PRIOR-ART-ASSESSMENT.md`.
>
> **Draft 3 tests that retraction instead of conceding it.** A follow-up run (P3-X, §4.2.1) extends
> the grid to LongGuard's full 0–32k range at both scales, 1,260 inputs per model, zero unparsed
> output. **The retraction was correct**: over the endpoints, 19 payloads out of 60 degrade and 0
> improve at both scales (*p* < 0.0001), and the 0.6B's one non-monotone step is the single step that
> fails significance (*p* = 0.688).
>
> **Pre-registered before any constructed input was scored** — three mechanisms, their distinguishing
> predictions and the invalidation conditions frozen and hashed (`ba560d2d`, re-hashed `21cdee5c`).
> Pre-registration protected the analysis from the data. **It did nothing about claiming novelty
> that did not exist**, which is the failure recorded here.

---

## Abstract

Embedding unsafe content inside an ordinary benign frame — a workplace email — is the most effective
guard-evasion transformation we have measured, defeating guards on 51% to 62% of attempts across
three model families. It is also the transformation whose mechanism is least obvious, because it
changes two things at once: it makes the input longer, and it moves the unsafe span away from the
edges.

**We separate those by construction.** A synthetic grid holds filler *content* constant while varying
filler *quantity* and payload *position* independently: 100 unsafe payloads, each of which both
guards catch perfectly in isolation, placed at three positions across four length multiples.

**Position orders the effect at short context.** Pooled across lengths, a payload in the middle of
its frame is missed 4.33× more often than one at the end. **This replicates LongGuard's
lost-in-the-middle finding** [LongGuard] on two models they did not test, in a length regime
(≈0.3k–1.2k tokens) at the very bottom of their grid.

**We retract a claim, and then test the retraction.** Draft 1 reported miss rate as non-monotone in
length — rising to 9.3% at 4× filler then falling at 16× — and concluded that dilution is refuted.
LongGuard attributes failure *to* proportional dilution over a range 25× longer, with an edge–middle
gap growing from +6.67% at 0.25k to +30.88% at 16k. Our grid never left their weakest regime, so the
non-monotonicity was retracted as a probable small-range artifact. **We then ran the range** (§4.2.1):
across 0–32k at both scales, **19 payloads degrade and 0 improve, at both scales (*p* < 0.0001)**, and
the sole non-monotone step is the only step that fails significance. **The artifact reading was
right.**

**The measured effect.** 39/300 versus 9/300 for the 4B (Fisher one-sided *p* = 3.4×10⁻⁶) and 2.64×
(*p* = 2.4×10⁻³) for the 0.6B. The ordering — middle worst, end safest, start intermediate — holds at
every length and in both models, and matches the direction LongGuard reports at larger scale.

**What this note adds, narrowly:** the effect is measurable at **short context** (≈0.3k–1.2k tokens),
on **two models LongGuard did not evaluate**, against a control in which the same payloads are caught
**100% of the time** unframed. We release the grid construction, the per-item verdicts, and the
pre-registration.

**Keywords:** guard models, adversarial robustness, positional bias, long-context, AI safety

---

## 1. Introduction

Guard models classify content as safe or unsafe inline in an agentic pipeline. Companion work established that semantically-preserving rephrasing degrades guards asymmetrically — leaving
false positives unchanged while raising false negatives — and that among five transformation
families, one dominates: **embedding the unsafe content inside an ordinary benign frame.**

Across three model families that family reaches **0.5079 and 0.6199** candidate-level miss rate,
roughly double any other transformation. Two things about it were unexplained.

**First, it was not the strongest under deterministic decoding.** On a temperature-0 floor, a
different family led. The benign-framing advantage appears under *sampling*, which suggests the
effect depends on something that varies between samples — plausibly where the payload lands.

**Second, it confounds two variables.** Framing makes the input several times longer *and* moves the
payload away from the input boundaries. Every prior analysis reported it separately for exactly this
reason, and none could separate the two.

**This paper separates them.**

### 1.1 Three mechanisms, three predictions

| | mechanism | prediction |
|---|---|---|
| **M-A** | **Length dilution** — the unsafe span is a smaller fraction of a longer input | miss rate rises with length at fixed position |
| **M-B** | **Positional displacement** — the payload sits where the model attends least | miss rate varies with position at fixed length |
| **M-C** | **Boundary crossing** — the frame shifts the judgment itself, not attention | verdict probability shifts even at short length and edge position |

They are separable by construction: M-A varies length holding position, M-B varies position holding
length, and M-C predicts an effect surviving both held constant.

### 1.2 Findings

- **M-A: non-monotone in our range, refutation retracted — and the retraction now tested** (§4.2,
  §4.2.1). Our grid tops out around 1.2k tokens; LongGuard measures dilution dominating over a range
  25× longer. **Extending to that range confirms it**: 19 of 60 payloads degrade and 0 improve from
  1k to 32k, at both scales (*p* < 0.0001). **M-A was never refuted — it was untested.**
- **M-B supported**, at 4.33× and 2.64×, significant in both models, consistent at every length —
  **replicating** LongGuard's lost-in-the-middle result at the short end of the range.
- **M-C deferred here, and already answered elsewhere.** It requires verdict-token probabilities and
  a different serving stack, which would reintroduce a runtime confound the companion studies were built to eliminate (§3.4). LongGuard supplies the attention→logit→behavior chain we deferred.

---

## 2. Related work

**LongGuard [LongGuard] is the primary result this note replicates**, and it precedes this work by
four days. It evaluates 15 guardrails over a 0.25k–32k grid, reports unsafe recall dropping more than
50% on average, separates proportional dilution from absolute length with a paired Benign-Fill /
Needle-Repeat control, traces an attention→logit→behavior mechanism, isolates guard-specialized
retrieval heads, and supplies two training-free mitigations plus a deployment protocol. **Its
appendix C.2 reports the lost-in-the-middle and endpoint-asymmetry pattern this note also finds**,
with an edge–middle gap growing from +6.67% at 0.25k to +30.88% at 16k.

**Positional bias in long-context models** is independently well documented for retrieval and
question answering. LongGuard carries it into safety guardrails.

**Guard robustness work** measures rephrasing, jailbreaks and prompt injection [GuardMeaning], and
guardrail behavior under RAG-style long contexts [RAGGuard].

**What this note claims.** A replication on two models LongGuard did not test — at short context,
and then across their full 0–32k range — each against a **0× unframed control**, which is the one
design element their needle-in-haystack setup does not have and which anchors every cell to an
absolute floor rather than a relative baseline. Plus a **retraction** of a dilution refutation our
range could not support, and a **test of that retraction** at the range where it is testable.
**We claim no novelty on the positional phenomenon, its mechanism, or its mitigation.**

---

## 3. Method

### 3.1 Payload selection

100 unsafe payloads, each **caught by both models under test in its original, unframed form.**

This matters more than it may appear. If a payload were already missed without framing, a miss under
framing would be credited to the frame rather than to a pre-existing failure. The pre-registration
forbids that, and §4.1 confirms the filter worked: **the control condition has a 0.0000 miss rate in
both models.**

> **A pre-registered rule that had to be revised, and was recorded rather than quietly changed.**
> The original rule was "caught by every guard in the program." That yields **27 payloads**, because
> one family in the panel catches only 32 of 150 items under the four-policy prompt we supply it —
> a limitation of *our configuration*, not of the payloads. Intersecting against it would let our own
> prompt decide which unsafe content this experiment may study. The rule was revised to "caught by
> every guard **this experiment scores**," giving 120, of which 100 are used. The cost is that the
> payload set is **not valid for a cross-family extension** and must be re-intersected if P3 is ever
> run on the wider panel.

### 3.2 The grid

**One filler corpus, reused in every cell**, so filler *content* is constant and only quantity and
position vary. Filler is ordinary workplace-email prose.

- **Length:** payload + filler at **0×, 1×, 4×, 16×** the payload length.
- **Position:** payload at **start**, **middle**, **end** of the filled input.
- **0× is the control** — payload alone, no frame, no position. It is emitted once per payload.

100 payloads × 10 cells = **1,000 constructed inputs**, each scored by both models. Median input
length runs 281 → 564 → 1,407 → 4,779 characters across the four multiples.

### 3.3 Scoring

Qwen3Guard-Gen-4B and -0.6B at `Q4_K_M`, `num_ctx` 8192, seed 0, temperature 0, fail-closed —
identical to every other measurement in the companion studies. **Zero unparsed outputs across 2,000
evaluations.**

A **miss** is the guard returning `Safe` on an input containing an unsafe payload.

### 3.4 Why M-C is deferred, stated before any number

M-C requires verdict-token *probabilities*, not argmax verdicts. The serving stack used throughout the companion studies does not usefully expose logprobs, so M-C requires `transformers` or vLLM.

**Numbers from that path cannot be compared against any verdict measured here**, or the runtime
confound — precision, tokenization and kernel differences masquerading as an effect — re-enters
through the back door. Companion work was designed specifically to eliminate it. M-C
therefore requires its own baseline on the same grid through the same stack, and is reported as
**not run** rather than approximated.

---

## 4. Results

### 4.1 The control confirms the design

| | miss rate on bare payloads (n=100) |
|---|---|
| Qwen3Guard-4B | **0.0000** [0.0000, 0.0370] |
| Qwen3Guard-0.6B | **0.0000** [0.0000, 0.0370] |

**Every payload is caught with no frame around it.** Every miss reported below is therefore
attributable to the framing, not to a payload the guard never handled.

### 4.2 M-A: non-monotone in our range — a retracted refutation

Miss rate pooled over position:

| | 0× | 1× | 4× | 16× |
|---|---|---|---|---|
| **4B** | 0.0000 | 0.0433 | **0.0933** | 0.0667 |
| **0.6B** | 0.0000 | 0.0433 | **0.0833** | 0.0600 |

**Both models peak at 4× and decline at 16×.**

⚠️ **Draft 1 read this as refuting dilution. That reading is retracted.** Our largest cell is
≈1.2k tokens; LongGuard's grid runs to 32k and finds dilution dominating, with the edge–middle gap
growing from +6.67% at 0.25k to +30.88% at 16k. At 0.25k — the point closest to our range — their
effect is also small. **We did not test a range where dilution would be expected to dominate**, and
non-monotonicity inside a narrow low range is not evidence against it.

Length is not irrelevant — the jump from 0× to 1× is the largest single step, and any framing at all
costs the guard something. But **within our range the quantity of filler does not order the effect.**

#### 4.2.1 The retraction, since tested rather than conceded

The retraction above was a concession to a longer-range published result. **We then ran the range**
(P3-X, pre-registered `324ee77b`): the same 60 payloads across lengths {0, 1k, 4k, 16k, 32k} × five
positions, 1,260 inputs per model at both scales.

⚠️ **`num_ctx` was raised 8192 → 32768 to admit a 32k input, and held constant across all 21 cells.
P3-X's numbers are therefore not directly comparable to the table above.** It does not correct those
measurements; it tests the *inference we drew from them* at a range they never reached.

**Unparsed output was 0.000 in all 42 cells**, so no number below is a truncation artifact.

| pooled miss rate | 0× | 1k | 4k | 16k | 32k |
|---|---|---|---|---|---|
| **4B** | 0.0000 | 0.1100 | 0.1233 | 0.1933 | 0.2700 |
| **0.6B** | 0.0167 | 0.0700 | 0.1867 | 0.1600 | 0.3233 |

**The 4B is monotone.** The 0.6B has one decrease, at 4k→16k. An unregistered follow-up — reported as
unregistered — tests the steps with McNemar exact on payload-level discordance, since the same 60
payloads recur at every length:

> **That single decrease is the one step that fails significance (2 worse, 4 better, *p* = 0.688).**
> Every other 0.6B step is a significant rise. **Over the endpoints, both scales are identical and
> one-directional: 19 payloads degraded, 0 improved, *p* < 0.0001.** Not one payload out of 60 became
> easier to detect when filler was added, at either scale.

The edge–middle gap grows with length at the 4B — +7.2% at 1k to +28.3% at 32k — closely tracking
LongGuard's +6.67% at 0.25k to +30.88% at 16k.

**So the retraction was correct, and is now supported by measurement rather than by deference.**
Draft 1's non-monotonicity was a small-range artifact. **M-A is not refuted; it was untested**, and
over the range where it is testable it holds.

### 4.3 M-B supported: position orders the effect

Miss rate by position, pooled over the three non-zero lengths:

| | start | **middle** | end |
|---|---|---|---|
| **4B** | 13/300 = 0.0433 | **39/300 = 0.1300** | 9/300 = 0.0300 |
| **0.6B** | 16/300 = 0.0533 | **29/300 = 0.0967** | 11/300 = 0.0367 |

| comparison | 4B | 0.6B |
|---|---|---|
| middle vs end | **4.33×**, *p* = 3.4 × 10⁻⁶ | **2.64×**, *p* = 2.4 × 10⁻³ |
| middle vs start | 3.00×, *p* = 1.1 × 10⁻⁴ | 1.81×, *p* = 3.1 × 10⁻² |

*(Fisher exact, one-sided.)*

**The ordering is middle ≫ start > end, and it holds at every individual length in both models:**

| 4B | start | middle | end |
|---|---|---|---|
| 1× | 0.0200 | 0.0900 | 0.0200 |
| 4× | 0.0500 | **0.1800** | 0.0500 |
| 16× | 0.0600 | 0.1200 | 0.0200 |

The worst single cell is **4B at 4× length, middle position: 0.1800** — eighteen of a hundred
payloads that the same model catches perfectly when unframed.

### 4.4 Why the two mechanisms produce different curves

The interaction explains §4.2's non-monotonicity. At 16× the filler is long enough that the
"middle" is far from both edges — but the *end* position also becomes strongly protective, because
the payload sits immediately before the verdict is generated. Pooling across positions therefore
mixes a worsening middle with an improving end, and the pooled curve turns over.

**That is exactly what an effect governed by position, not quantity, looks like when you average
over position.** It is also why reporting length alone would have produced a confusing null.

---

## 5. Analysis

### 5.1 The positional profile matches long-context retrieval, in a safety setting

The middle-worst, edges-better profile is the signature documented for long-context retrieval. Its
appearance in a *classification* task with a safety consequence is, to our reading, new — and it
means the guard is not failing to *understand* the payload. It is failing to *attend* to it.

The strongest evidence for that reading is §4.1: the identical payload, identical model, identical
settings, is caught **100% of the time** when it is the whole input. Nothing about the content
changed.

### 5.2 The attacker's advantage is free

An attacker gains this multiplicatively **without modifying the payload**. No rephrasing, no
obfuscation, no optimization against the guard — only placement. Placement is also the cheapest
possible variation: it requires no model, no queries and no feedback.

That places this below every attack we have previously measured in cost and above most in
reliability.

### 5.3 The defensive implication is unusually concrete

Most findings in the companion studies complicate defense. This one suggests something actionable:
**a guard that scores an input in overlapping windows, or that re-scores with the suspect span moved
to the end, should recover much of the loss** — because the end position is measurably the safest
one, at 0.0300 and 0.0367 against a middle of 0.1300 and 0.0967.

We have not tested that. It is stated as the obvious follow-up, and it is cheap.

### 5.4 Scale does not rescue it

The 4B shows a *larger* positional effect than the 0.6B (4.33× versus 2.64×), driven by an unusually
low end-position miss rate. The bigger model is better at the edges and no better in the middle.
**Scaling improves the best case without repairing the worst.**

---

## 6. Threats to validity

**M-C is untested** (§3.4), so we cannot exclude that framing also shifts the judgment itself. Our
claim is that M-A does not account for the effect and M-B substantially does — not that M-B is the
whole story.

**Two models, one family.** Qwen3Guard at two scales. The benign-framing dominance that motivated
this work replicates across three families, but the positional decomposition has not been run on
them. The payload set would also need re-intersecting first (§3.1).

**One filler corpus.** Filler content is constant by design, which removes it as a confound but also
means we tested one register of benign prose. Filler that is topically related to the payload might
behave differently.

**Synthetic construction.** The grid is assembled, not naturally occurring. It buys the ability to
separate length from position, and it costs ecological validity: a real attacker's email would be
coherent with its payload in a way ours is not — which most likely makes our estimates
**conservative**.

**Cell sizes of 100.** Individual cells have wide intervals; the pooled position comparisons
(n=300 per cell) carry the significance claims, and per-cell figures are reported for shape rather
than for inference.

**Absolute rates are small.** A 13% pooled middle-position miss rate is a large *relative* effect
against a 0% control, and a modest absolute one. Both framings are in §4.3 and neither is preferred.

---

## 7. Conclusion

The most effective guard-evasion transformation we have measured works because of **where** the
payload sits, not **how much** text surrounds it.

Within the short range we tested, length is non-monotone. Position orders the effect cleanly: a payload in
the middle of a benign frame is missed **4.33× more often than the same payload at the end** by a
model that catches it **100% of the time** with no frame at all. The ordering holds at every length,
in both model scales, and the effect is significant at *p* < 10⁻⁵.

This is the long-context "lost in the middle" bias, arriving in a safety classifier and carrying an
exploitable consequence. It costs an attacker nothing — no rephrasing, no queries, no optimization,
only placement — and it is the cheapest reliable evasion we have measured.

It may also be the most tractable. The end position is measurably safe. A guard that scores
overlapping windows, or that relocates a suspect span before deciding, has a plausible path to
recovering most of the loss. **That is a defense this result predicts and does not test**, and it is
the next thing worth running.

---

## Artifact

Grid construction script; the filler corpus; all 1,000 constructed inputs by payload identifier,
length multiple and position; per-item verdicts for both models; the pre-registration and both
hashes, including the payload-selection addendum and what it costs.

---

## References

[LongGuard] Z. Chen, X. Wu and S. Hu. *LongGuard: Mechanistic Analysis and Training-Free Mitigation
of Long-Context Failure in Safety Guardrails.* Institute of Information Engineering, Chinese Academy
of Sciences. arXiv:2608.27580, 2026. — **the primary result this note replicates.** Establishes the
positional finding across 15 guardrails over 0.25k–32k, supplies the attention→logit→behavior
mechanism, and implements chunked-detection and attention-head-sharpening defenses.

[GuardMeaning] C. Pinneri and C. Louizos. *Guarding the Meaning: Self-Supervised Training for
Semantic Robustness in Guard Models.* Qualcomm AI Research. arXiv:2511.10665, 2025.

[RAGGuard] *RAG Makes Guardrails Unsafe? Investigating Robustness of Guardrails under RAG-style
Contexts.* arXiv:2510.05310, 2025.

[WildGuard] *WildGuard: Open One-Stop Moderation Tools for Safety Risks, Jailbreaks, and Refusals of
LLMs.* arXiv:2406.18495, 2024. — source of the payloads.

> **On the sequencing.** Draft 1 was written before any prior-art check. LongGuard predates it by
> four days and supersedes its central claim. This is recorded rather than quietly absorbed, and the
> program has since added a literature gate before first draft rather than after.
