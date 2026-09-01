# Guard model inventory — reconciled against what exists

**2026-09-01.** The roadmap says one fine-tune was attempted and rejected, three
models are GPU-blocked and four are cold-start blocked on warrant history.

**Six fine-tuned adapters exist and all six have been evaluated against the full
corpora.** None of that is recorded anywhere.

> **Updated later the same day.** One adapter appeared to clear every promotion
> criterion. It does not survive inspection — W1 found its severity field
> flattened, and W3 found the two 4B adapters statistically within noise.
> **Nothing here is promotable.** Findings in `W1-W3-findings-2026-09-01.md`;
> corrections are marked in place below rather than rewritten away.

---

## 1. What actually exists

`ollama list` — 13 models, of which 8 belong to this programme:

| Model | Size | Built |
|---|---|---|
| `hf.co/mradermacher/Qwen3Guard-Gen-4B-GGUF:Q4_K_M` | 2.72 GB | 2026-08-13 *(baseline)* |
| `hf.co/mradermacher/Qwen3Guard-Gen-0.6B-GGUF:Q4_K_M` | 0.48 GB | 2026-08-13 *(baseline)* |
| `warrantor-guard-0.6b-weak-category-catonly-2026-08-13b` | 0.50 GB | 2026-08-13 |
| `warrantor-guard-0.6b-adversarial-adv06-2026-08-22a` | 0.50 GB | 2026-08-22 |
| `warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a` | 0.50 GB | 2026-08-22 |
| `warrantor-guard-0.6b-weak-category-local-2026-08-22a` | 0.50 GB | 2026-08-22 |
| `warrantor-guard-4b-adversarial-adv4b-2026-08-22a` | 2.78 GB | 2026-08-22 |
| `warrantor-guard-4b-weak-category-weak4b-2026-08-22b` | 2.78 GB | 2026-08-22 |

`eval_results/` — seven result documents, all full-corpus, none referenced by any
roadmap or paper.

---

## 2. The baselines reproduce

Two runs on 2026-08-21 measured the **base** models against the pinned baselines:

| Corpus | Measured 08-21 | Pinned baseline | Delta |
|---|---|---|---|
| WildGuardTest 4B | 0.8568 | 0.8554 | **+0.0014** |
| ExpGuardTest 4B | 0.7588 | 0.7596 | **−0.0008** |

Both within one or two items on denominators of 753 and 1,256. **The pinned
figures are sound**, which is R1's question already answered once — R1 is
re-running it to confirm the answer still holds today.

---

## 3. Five of six adapters do not beat their baseline

Each compared to the correct baseline — matching corpus *and* model size:

| Adapter | Corpus | Size | Recall | Baseline | Delta |
|---|---|---|---|---|---|
| **`0.6b-expguard-weak-exp06`** | ExpGuard | 0.6B | **0.7818** | 0.7150 | **+0.0668** |
| `4b-adversarial-adv4b` | WildGuard | 4B | 0.8607 | 0.8554 | +0.0053 |
| `4b-weak-category-weak4b` | WildGuard | 4B | 0.8541 | 0.8554 | −0.0013 |
| `0.6b-adversarial-adv06` | WildGuard | 0.6B | 0.8369 | 0.8488 | −0.0119 |
| `0.6b-weak-category-local` | WildGuard | 0.6B | 0.7374 | 0.8488 | **−0.1114** |

`0.6b-weak-category-local` lost **11 points of recall**. That is a failure worth
its own post-mortem — it is the same magnitude as the 17-point drop that refuted
`supervise_severity=False`, and nothing records it.

> **A delta is not a verdict.** Per this project's own doctrine, an ordering
> without a significance test is not a finding. The four middle rows are all
> within plausible noise on these denominators and should be treated as
> *unresolved*, not as small wins and losses.

---

## 4. The one that clears its bar — and why that is not enough

> **SUPERSEDED IN PART, same day.** Everything in this section is arithmetically
> correct and the conclusion drawn from it was wrong. W1 found that this adapter
> emits **zero `controversial` verdicts** where the base model emits 266 — the
> third severity class is extinguished. It clears every bar the gate states while
> having quietly become a different instrument. **Do not promote.** See
> `W1-W3-findings-2026-09-01.md`. The bars below are left unedited because the
> point is that they all passed.

`warrantor-guard-0.6b-expguard-weak-exp06-2026-08-22a`, ExpGuardTest,
2,275 rows: **TP 982 · FN 274 · FP 56 · TN 963**.

The promotion bar, computed in the recipe notes *before* the run:

> *"promotion needs at least **942 caught** (recall ≥ 0.7500, i.e. +44 rows) AND
> fewer than **116 false positives** (FPR below 0.1138). The minimum detectable
> delta is 0.0353."*

| Criterion | Required | Achieved | |
|---|---|---|---|
| Caught | ≥ 942 | **982** | ✅ +40 |
| False positives | < 116 | **56** | ✅ less than half |
| Recall | ≥ 0.7500 | **0.7818** | ✅ |
| Delta vs baseline | > 0.0353 | **+0.0668** | ✅ nearly double |
| FPR | below 0.1138 | **0.0550** | ✅ *improved* from 0.0873 |

### Per-category — including the two floors that were supposed to fall

| Category | Baseline | Candidate | Delta | |
|---|---|---|---|---|
| **Unqualified Professional Advice** | 0.3719 | **0.6281** | **+0.2562** | trained for |
| Privacy Violation | 0.4800 | 0.7200 | +0.2400 | trained for |
| Violence & Incitement | 0.6481 | 0.8704 | +0.2223 | trained for |
| Self-Harm & Suicide Promotion | 0.6607 | 0.8393 | +0.1786 | trained for |
| Criminal Planning | 0.8062 | 0.8287 | +0.0225 | **floor, untrained** |
| Fraud, Scams & Deception | 0.7629 | 0.7877 | +0.0248 | **floor, untrained** |

The recipe warned explicitly that Criminal Planning and Fraud *"are NOT trained
for by this recipe and can only fall"*, and that a gate exists precisely to catch
an aggregate that improves while a class collapses.

**Neither fell. Both rose.** Every trained category improved by 18 to 26 points,
and the weakest measured class in the entire programme — UPA at 0.3719 — nearly
doubled.

---

## 5. What this changes

1. **The programme is further along than any document says.** Six adapters
   trained, six evaluated. ~~one apparently promotable~~ — **none promotable**:
   W1 showed the apparent winner flattened its severity field, and W3 showed the
   two 4B adapters are statistically within noise (*p* = 0.55 and *p* = 0.79). The
   roadmap's "one attempted and rejected" describes August 13, not August 22.
2. **Modal spend for the ExpGuard recipe is still unnecessary**, for a different
   reason than first given: not because the recipe succeeded, but because it can be
   run locally and the result needs a severity fix rather than more GPU.
3. ~~The cold-start framing needs re-checking~~ — **checked, and it is real.**
   `guard export-corpus` returns **0 rows from 0 warrants** against a recipe
   minimum of 500. All four substrate recipes are genuinely blocked on product
   usage.
4. ~~**One adapter regressed 11 points** and nobody knows why.~~ **Solved by W2**:
   category vocabulary leaked into the severity slot and mass shifted from
   `unsafe` to `controversial`. McNemar χ² = 66.01, *p* < 0.0001.

---

## 6. What I have NOT done, and will not claim

- **I have not run `parity_gate`.** The arithmetic above compares against the
  recipe's own stated bar; the repository's actual gate takes a `CandidateResult`
  with lane, precision and manifest digest, and those are not recorded in the
  result documents. **Until the real gate runs, this is a strong candidate, not a
  promotion.**
- **No significance test.** The +0.0668 exceeds the pre-computed minimum
  detectable delta of 0.0353, which is the recipe's own bar — but a McNemar test
  on paired item-level outcomes is what would settle it, and it has not been run.
- **Commercial clearance still does not exist.** ExpGuardMix's gate form affirms
  research-only use, narrower than its CC-BY-4.0 licence. A promotion here is a
  quality verdict and never a clearance for a shipped pack.

## 7. Next steps — status after W1–W3

| | Step | Status |
|---|---|---|
| 1 | `parity_gate` on the ExpGuard candidate | **Moot.** The severity check settles it: do not promote. |
| 2 | McNemar to convert +0.0668 into a result | **Blocked** — needs a 0.6B ExpGuard baseline run, which does not exist on disk. Local and free. |
| 3 | Post-mortem the 11-point regression | ✅ **Done.** Severity-field contamination; χ² = 66.01, *p* < 0.0001. |
| 4 | Correct the roadmap and memory | Outstanding. |
| 5 | Re-check the cold-start framing | ✅ **Done.** Genuinely blocked — 0 rows, 0 warrants. |

**The cheapest useful work remaining** is two local baseline runs — the 0.6B on
WildGuardTest and on ExpGuardTest — which make every 0.6B comparison paired and
correctly size-matched. Free, no hypothesis required, and they unblock step 2.
