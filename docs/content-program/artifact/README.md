# Artifact — What Guard Benchmarks Cannot See

Replication artifact for *What Guard Benchmarks Cannot See: Six Controlled Experiments in Guard
Model Evaluation*.

**Every experiment in this bundle was pre-registered and hashed before its data existed.** The
hash chain in §4 is the load-bearing claim of this artifact: it is what distinguishes a
pre-registered null from a null discovered after the fact, and it is checkable without trusting us.

---

## 1. What is here

| Directory | Contents |
|---|---|
| `prereg/` | Six pre-registration documents, their SHA-256 files, and dated addenda |
| `results/` | One `RESULTS.md` per experiment — the reported numbers and their caveats |
| `code/` | Modal apps, corpus builders, analyzers, evaluation harness |
| `specs/` | Frozen transformation specifications, prompt templates, per-family parsers |
| `verdicts/` | Per-item model outputs for every condition in every experiment |
| `manifests/` | Model BOMs, dataset manifests, environment pins, corpus digests |
| `ids/` | Source row indices into WildGuardMix, for reconstructing item sets |

**Read `LICENSING.md` before using the data.** The bundle is deliberately two-tier: Aegis-derived
material ships (CC-BY-4.0), WildGuardMix-derived source text does not (ODC-By plus a click-through
gate). Item IDs and regeneration scripts are included so every result remains reproducible.

## 2. The experiments

| | Question | Headline |
|---|---|---|
| **E2** | Does rephrasing raise false positives? | No — 1.00× [0.45, 4.20]. A **withdrawn** pre-registered finding. |
| **E2-B** | Does the same rephrasing raise false negatives? | Yes — 1.42×/1.46×, McNemar p ≈ 10⁻⁵, 6:1 asymmetric |
| **M2** | How far is the adversarial ceiling above that floor? | 77.0%/85.4% of caught items evaded; most of the gap is decoding **temperature**, not budget |
| **M3** | Does quantization change safety verdicts? | Yes, at the deployed `Q4_K_M` default |
| **M3-X** | Does that hold in other families? | *(see `results/`)* |
| **M1** | Does the asymmetry hold across families? | Yes — three families, three publishers; evasions **transfer** at 2.5–6× |
| **E1** | Does category specialization help? | No — it **hurts**, with no gain on the targeted categories |
| **E3** | Are verdicts sensitive to context configuration? | No — and *why* not is the finding. A **withdrawn** pre-registered finding. |

## 3. Reproducing a result

```bash
# 1. Accept the WildGuardMix gate on Hugging Face and export a read token.
#    (Aegis needs no gate — CC-BY-4.0, ungated.)
export HF_TOKEN=...

# 2. Rebuild the item sets from the published row indices.
python code/build_items.py --ids ids/ --out items/

# 3. Verify they match what we ran, by digest.
python code/verify_digests.py --items items/ --manifest manifests/corpus-digests.json

# 4. Re-run any condition. Specs and seeds are frozen; nothing is chosen at run time.
python code/evaluate.py --eval-set items/unsafe-reph.jsonl \
    --model <tag> --num-ctx 8192 --seed 0 --out out.json

# 5. Re-run the analysis. Every analyzer was written BEFORE its data existed.
python code/analyze_<experiment>.py
```

**The analyzers are part of the pre-registration, not a convenience.** Each was written and
committed before the run it analyzes completed, which is why the reported quantities are the ones
that were promised rather than the ones that turned out well.

## 4. The hash chain

| Experiment | Hash | Frozen before |
|---|---|---|
| E2 transformation set v2 | `48ce3dae` | any guard saw any output |
| E2-B evasion arm | `cdc94f66` | any unsafe item was rephrased |
| M2 adversarial ceiling | `237e8f44` → `9a3ae674` | any candidate was generated |
| M3 quantization | `b26c2bf6` → `ca0a2286` | any corpus was built |
| M1 cross-family panel | `319bc541` → `fb410831` | any non-Qwen3Guard model ran |
| M3-X quantization panel | `c4dbf173` | any non-Qwen3Guard model ran at any precision |
| E1 amendment | `9240fabd` → `0df38fc3` | any training run started |

**Second hashes are dated addenda. Amendments are appended and re-hashed, never edited**, so the
ordering stays auditable. Verify with:

```bash
cd prereg && sha256sum -c *.sha256
```

An addendum always states what changed, why, and what was known at the time. Three of them record
design changes forced by defects found mid-experiment — a corpus with an empty-text row, a
transformation set whose generator returned its input unchanged, a training corpus that came out
100% unsafe — and each says so.

## 5. What we got wrong, collected in one place

An artifact that only contains successes is not evidence of method. `results/NEGATIVE-RESULTS.md`
lists, with reasons:

- Two **pre-registered findings withdrawn** on our own data (E2's false-positive amplification,
  E3's context confound).
- A **recorded infrastructure claim that did not reproduce** (a 32768 context does not exhaust a
  16 GB card).
- **Transformation set v1**, in which two of five families silently returned the input unchanged —
  the API success flag reported transport success, not semantic change.
- **The first `G-cat` construction**, 100% unsafe, caught before training rather than after.
- An internal analysis that claimed E2 "refutes" a circulated 4.12× figure, **corrected** to *no
  support for, under-powered to exclude*.
- Rejected training runs from earlier in the program, with their rejection reasons.

## 6. Known limitations, stated here and not only in the paper

- **Single family for four of six experiments.** M1 establishes the asymmetry across three families;
  the quantization ladder, specialization, ceiling and context sweep were each run on one.
- **ShieldGemma's absolute rates reflect our prompt.** We supply a four-policy formulation against a
  corpus spanning more categories, so its baseline miss rate measures our configuration, not the
  model. Only within-model, within-prompt agreement is interpretable.
- **150-item arms.** The paired McNemar tests are robust to that; the point estimates are not.
- **The adversarial ceiling is best-of-16 selection**, not feedback-guided search. It bounds the
  floor from above, not the threat.
- **`f16` is a reference condition, not ground truth** about which verdict is correct.
- **Quantization is not held constant across families** in M1, only within each model in M3/M3-X.

## 7. Citation

```
@misc{guardbenchmarks2026,
  title  = {What Guard Benchmarks Cannot See: Six Controlled Experiments in Guard Model Evaluation},
  author = {Jha, Vikram},
  year   = {2026},
  doi    = {<assigned by Zenodo on publication>}
}
```

Attribution required by the source corpora is carried in `LICENSING.md` §6.
