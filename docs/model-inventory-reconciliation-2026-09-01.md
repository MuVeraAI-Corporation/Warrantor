# Guard model inventory — reconciled against what exists

**2026-09-01.** The roadmap says one fine-tune was attempted and rejected, three
models are GPU-blocked and four are cold-start blocked on warrant history.

**Six fine-tuned adapters exist, all six have been evaluated against the full
corpora, and one of them clears every stated promotion criterion.** None of that
is recorded anywhere.

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

## 4. The one that clears its bar

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
   trained, six evaluated, one apparently promotable. The roadmap's "one attempted
   and rejected" describes August 13, not August 22.
2. **Modal spend for the ExpGuard recipe is very likely unnecessary.** It was
   listed among the GPU-blocked models. It has already been trained, on the local
   5080, and it cleared its bar.
3. **The cold-start framing needs re-checking too.** If ExpGuard-weak trained
   without warrant history, the four "cold-start blocked" recipes deserve the same
   scrutiny before anyone waits on product usage for them.
4. **One adapter regressed 11 points** and nobody knows why.

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

## 7. Recommended next steps

1. Run the real `parity_gate` on `0.6b-expguard-weak-exp06`, reconstructing the
   lane and precision metadata from the run.
2. McNemar on paired outcomes against the baseline, to convert +0.0668 from a
   delta into a result.
3. Post-mortem `0.6b-weak-category-local`'s 11-point regression.
4. Correct the roadmap and `warrantor-build-decisions` memory, which both describe
   a programme two weeks out of date.
5. Re-check the four "cold-start blocked" recipes against what actually trained.
