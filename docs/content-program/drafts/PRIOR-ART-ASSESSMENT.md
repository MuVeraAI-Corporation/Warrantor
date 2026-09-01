# Prior-art assessment — what survives, what does not

**Written 2026-08-31 03:40, autonomously, before any of these papers was submitted anywhere.**

I searched the guard-model literature for the first time tonight. **I should have done this before
writing the papers, not after.** A memory note in this project already warned that the reading list
was stale — six arXiv references, newest March 2025 — and that the 2026 cluster held prior art. I
wrote three papers without acting on it.

**Several novelty claims do not survive. One paper is comprehensively pre-empted.** This document
states what changes, paper by paper, with the citations.

---

## 1. The finding that matters most: P3 is pre-empted

**LongGuard: Mechanistic Analysis and Training-Free Mitigation of Long-Context Failure in Safety
Guardrails.** Chen, Wu & Hu, Institute of Information Engineering, Chinese Academy of Sciences.
arXiv 2608.27580, **published 2026-08-27 — four days before P3 was written.**

| | LongGuard | P3 (ours) |
|---|---|---|
| Guardrails | **15** | 2 |
| Length grid | **0.25k–32k tokens** | ~0.3k–1.2k tokens |
| Position varied | **yes** (0/25/50/75/100%) | yes (start/middle/end) |
| Lost-in-the-middle found | **yes**, edge–middle gap +6.67% at 0.25k rising to **+30.88% at 16k** | yes, 4.33× middle vs end |
| Mechanism | **attention → logit → behavior chain, measured** | deferred as M-C, not run |
| Defense | **Chunked Detection + Attention-Head Sharpening, +22%/+13%** | "predicted, not tested" |

**Every element of P3 exists in LongGuard at greater scale, plus the mechanism P3 deferred and the
defense P3 only predicted.**

**Worse, P3's one apparently-contrarian result is probably an artifact of our narrow range.** P3
claims to refute length dilution because miss rate is non-monotone, peaking at 4× and falling at 16×.
LongGuard's paired Benign-Fill / Needle-Repeat design attributes failure *to* proportional dilution,
over a range 25× longer. Our grid tops out around 1.2k tokens — inside the regime where LongGuard
measures only a +6.67% edge–middle gap. **We likely never reached the range where dilution
dominates, and reported that as a refutation.**

**Recommendation: P3 is not publishable as novel work.** Options, in order of honesty:
1. **Withdraw it.** The cleanest response.
2. Reframe as a **short replication note** — the positional effect reproduces at short context on
   two models LongGuard did not test — and cite LongGuard as the primary result. This is a workshop
   contribution at most.
3. Extend to LongGuard's range and models to test whether our non-monotonicity survives. That is a
   different, larger experiment, and it would still be a follow-up to their work.

---

## 2. T-03's headline phenomenon has prior art; the asymmetry may not

**Guarding the Meaning: Self-Supervised Training for Semantic Robustness in Guard Models.**
Pinneri & Louizos, Qualcomm AI Research. arXiv 2511.10665, **2025-11**.

They show that **meaning-preserving paraphrases cause large fluctuations in guard safety scores**,
name the phenomenon a **label flip** ("flipping a 'safe' classification to 'unsafe', or vice versa"),
analyze **six open-source guard models**, and — importantly — **propose a defense that works**,
reducing semantic variability by ~58% and improving benchmark accuracy ~2.5%.

**What this costs T-03:**
- The claim that rephrasing destabilizes guard verdicts is **not novel**. It is established.
- T-03 §2's gap list, which asserts prior work "does not report rephrasing effects separately for
  the false-positive and false-negative directions", must be **verified against this paper
  specifically** rather than asserted.

**What may survive, and it is the paper's best remaining claim:** they report flips in both
directions; we measure that the two directions are **wildly unequal** — benign FPR unchanged at
1.00×, unsafe FNR at 1.42×/1.46× with 6:1 item-level discordance and McNemar p ≈ 10⁻⁵, replicated
across three families. **That asymmetry is what T-03 should lead with**, and its novelty depends on
a careful reading of their Section 4, which I have not done.

**It also weakens D1 and P2.** T-03 now sits alongside a paper with a *working* defense. Our
contribution there is that two specific defenses fail and why — which is still worth reporting, but
it is a footnote to their result rather than an opening.

---

## 3. M3's novelty claim is wrong as written

**The Joint Effect of Quantization and Sampling Temperature on LLM Safety Alignment: A Factorial
Analysis.** arXiv 2606.29581, **2026-06-28**. Abstract: *"Modern LLM deployments often combine
quantization with higher sampling temperatures... yet safety evaluations usually treat these as
fixed implementation details."*

That is nearly verbatim T-03 §6.4's argument. Related: **Q-resafe** (2506.20251, quantization safety
risks and patching), **Preserving Fairness and Safety in Quantized LLMs** (2601.12033), and **How
Quantization Shapes Bias in LLMs** (2508.18088).

**T-03 §2 currently claims prior work "does not state or control serving quantization." That claim
is false and must be removed.** It is flagged in the production notes as the load-bearing novelty
argument for M3, asserted from our own reading — and the reading was wrong.

**What may survive:** M3's specific design controls *runtime* while varying only weights, uses one
publisher's ladder including an f16 reference, and reports **per-item verdict agreement** rather than
aggregate rates. Whether that specific contribution is novel requires reading 2606.29581 properly.

---

## 4. E1 has adjacent prior art

**When Safety Geometry Collapses: Fine-Tuning Vulnerabilities in Agentic Guard Models.**
arXiv 2605.02914. *"A guard model fine-tuned on entirely benign data can lose all safety alignment —
not through adversarial manipulation, but through standard domain specialization."*

**Not identical to E1.** They fine-tune on benign data; E1 holds label balance constant at 71.4% and
varies only the *composition of the unsafe half*. Different manipulation, related conclusion.
**E1's specific contrast may survive, but the framing "specialization can hurt" is not new** and
must cite this.

---

## 5. What appears to survive

**P1 (reproducibility floor).** I found no prior work measuring run-to-run verdict agreement for
guard classifiers at fixed configuration. The nearest neighbors concern serving nondeterminism
generally, not its cost to a safety decision. **P1 is the most likely of the new papers to be
genuinely novel**, and it is also the smallest claim.

**T-04 (field masking).** Unaffected by anything found here. Its own related-work section already
positions against a concurrent result.

**T-12 (systematization).** Unaffected; it is a systematization and its value is the argument.

**The cross-family transfer result** (evasions transfer at 2.5–6×, undermining defense-in-depth
independence). I found no prior art and it is T-03's most under-claimed finding.

---

## 6. What I am doing about it

1. **T-03 §2 rewritten** to remove the four asserted gaps and cite the real literature; the paper
   repositioned around the **asymmetry**, **transfer**, and **floor-vs-ceiling decomposition**
   rather than around "rephrasing destabilizes guards."
2. **P3 withdrawn from the submission set** pending a decision between the three options in §1.
3. **Real reference sections added** to P1 and T-03; P1 and P3 currently have none at all.
4. **M3's novelty claim deleted**, not softened.

## 7. The process failure, recorded

The papers were written across a single session, experiment-first, with the literature check left
until the end. **Every pre-registration in this program was frozen before its data — and none was
checked against prior art before its paper was written.** Pre-registration protects against fitting
the analysis to the data; it does nothing about claiming novelty that does not exist.

**The check costs one search and belongs before the first draft.** It has now been added to the
program's checklist as a gate, not a step.

---

## 4. P6 is pre-empted too — found BEFORE drafting this time

**Layered LLM Defenses as an Ensemble: Access Tiers, Inference Cost, and the Measured Failure
Correlation Between Defense Layers.** Alotaibi, Jabbar, Al-Azani & Ahmed, King Fahd University of
Petroleum and Minerals / SDAIA-KFUPM. arXiv:2608.28327v1, **published 2026-08-28 — three days before
P6's experiment ran.**

| | LayeredEns | P6 (ours) |
|---|---|---|
| Members | **7 heterogeneous defense layers** | 6 guard models, 3 publishers |
| Shared substrate | **yes** — all wrap one target model | **no** — standalone input classifiers |
| Pairs measured | 15 | 15 |
| All pairs correlated | **yes** (φ 0.30–0.75) | yes |
| Joint residual above multiplicative | **yes**, by up to 0.172 | yes, π = 51× |
| False refusals accumulate | **yes**, 4 in 5 benign refused | yes, FPR 0.50× predicted |
| Adversary | **one adaptive** | non-adaptive, frozen |
| Difficulty stratification | **runs it; most association dissolves** | runs it; **10/15 survive** |
| Mechanism claimed | **architectural** (shared substrate) | sampling (training lineage) |
| Apparatus | AATM + 5-class cost model, 58pp | none |

**The core thesis, the framing and the headline finding are theirs.** P6 claims none of them.

**What survives, and it is narrow:** their mechanism is explicitly architectural — "every member wraps
the same target model" — and they argue it is not attenuable by widening the member pool. **Our panel
has no substrate**, so by their own taxonomy it is the textbook ensemble case their account sets
aside. We find correlation persists, **survives their own difficulty control where theirs dissolves**,
and **tracks family lineage with no overlap** between within- and cross-family groups. That is
evidence for the sampling account in the setting where it should apply.

**Disposition: reframe as a replication-and-extension note, cite [LayeredEns] as primary.** Written
that way in `P6-composition-independence-paper.md`.

⚠️ **The process worked this time.** P3 was drafted first and the prior-art check came after, which
killed the paper and three claims. For P6 the check ran **before** the first draft, cost one tool
call, and did three useful things: it prevented a false novelty claim, it supplied the control we
were missing (difficulty stratification), and running that control produced the result the paper now
turns on. **The check is not a tax on drafting; it was the most productive step in this experiment.**

⚠️ **Open: our read of [LayeredEns] is partial** — abstract, §1, §2, §4.2–4.3, §10.5. Their §11
measurement sections are unread, and our contribution is defined by a contrast with their §11.6
result. **This must be closed before submission.**
