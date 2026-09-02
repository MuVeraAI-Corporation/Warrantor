---
license: cc-by-4.0
language:
  - en
tags:
  - guard-models
  - ai-safety
  - evaluation
  - reproducibility
  - llm-guardrails
task_categories:
  - text-classification
pretty_name: Guard Model Verdicts — per-item results for Qwen3Guard baselines and LoRA fine-tunes
size_categories:
  - 10K<n<100K
configs:
  - config_name: default
    data_files: verdicts.jsonl
---

# Guard Model Verdicts

**27,818 per-item guard verdicts across 14 evaluation runs, 10 model variants and 2 corpora.**

Guard-model papers report aggregate recall. This dataset publishes the layer underneath: **what each
model said about each item**, so that a reader can recompute the aggregates rather than trust them.

Author: **Vikram Jha**, MuVeraAI · ORCID [0009-0004-3959-6099](https://orcid.org/0009-0004-3959-6099)
· <vikram@muveraai.com>

## What is NOT here, and why that matters

**This dataset contains no prompt text.** Rows carry a positional `sample_id` (`egt-00000`,
`wgt-00000`), the ground-truth label, the model's verdict, its severity value and categories —
nothing from the underlying corpora.

That is deliberate. The corpora are **ExpGuardMix** (`6rightjade/expguardmix`) and **WildGuardMix**
(`allenai/wildguardmix`), both **gated**. ExpGuardMix's gate requires affirming research-only use,
which is narrower than its CC-BY-4.0 licence. Redistributing the items would route around that
gate.

**Joining back is easy for anyone who should be able to.** `sample_id` is the row's position in the
corpus's own test split, sorted by id. Accept the upstream gate, load the split, and the join is
positional. Nobody who has not accepted the gate gets corpus content from this dataset.

## Why the severity column is the interesting one

Every fine-tune in this programme damaged its severity field, and the damage is invisible to a
recall-only review.

| model | recall | FPR | `controversial` verdicts |
|---|---|---|---|
| Qwen3Guard-Gen-0.6B (base) | 0.7150 | 0.0854 | **122** |
| T1-A — LoRA, all 7 target modules | 0.7842 | 0.0589 | **0** |
| T1-B — LoRA, attention only | 0.8439 | 0.1649 | **0** |
| T1-C — LoRA, MLP only | 0.7930 | 0.0864 | **0** |

*ExpGuardTest, n = 2,275, `num_ctx` 8192, seed 0, greedy.*

Qwen3Guard emits a three-valued severity: `Safe`, `Unsafe`, `Controversial`. Every fine-tune here
emits two. **T1-B has the highest recall in the programme and is the worst model in it** — the gain
is substantially bought with false positives, and it has lost an output class. A `Controversial =
SAFE` policy control becomes a silent no-op on any of these models.

Attention-only and MLP-only are disjoint module families and each independently destroys the class,
so the loss is not attributable to a module family. The cause is the training target: the corpus
renders `Safety:` as a boolean, and 11,272 gradient updates teach a two-valued field.

## Files

| file | contents |
|---|---|
| `verdicts.jsonl` | 27,818 rows, one per (run, item). The flat table. |
| `runs.json` | Per-run metadata: metrics, sampling options, `result_digest`, schema version. |
| `runs/*.json` | The complete original result documents, verbatim. |

Fields: `run_id`, `corpus`, `model`, `sample_id`, `expected_unsafe`, `predicted_unsafe`,
`severity`, `categories`, `gated_by_category`, `errored`.

**`errored` matters.** The harness fails **closed** — a backend failure is scored as harmful — so an
errored row inflates recall. Exclude these rows before any paired comparison; the papers do.

## Reproducing the headline comparisons

```python
from datasets import load_dataset
import itertools, math

d = load_dataset("invincible-jha/guard-verdicts", split="train")
base = {r["sample_id"]: r for r in d if r["run_id"].startswith("baseline-0.6b")
        and r["corpus"] == "ExpGuardTest"}
cand = {r["sample_id"]: r for r in d if r["run_id"].startswith("T1-A")}

b_only = c_only = 0
for sid, b in base.items():
    c = cand.get(sid)
    if not c or not b["expected_unsafe"] or b["errored"] or c["errored"]:
        continue
    if b["predicted_unsafe"] and not c["predicted_unsafe"]: b_only += 1
    elif c["predicted_unsafe"] and not b["predicted_unsafe"]: c_only += 1

n, k = b_only + c_only, min(b_only, c_only)
p = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2**n)
print(b_only, c_only, p)        # 31 116 <0.0001
```

Paired exact-binomial McNemar, positives only, errored items excluded — the comparison the papers
run. Chi-square is not used: several comparisons here have fewer than 25 discordant pairs.

## Licence

**CC BY 4.0** — these are original measurements. The corpora they were measured on carry their own
licences and gates, which this dataset does not alter and does not redistribute.

## Citation

```bibtex
@misc{jha2026guardverdicts,
  author = {Vikram Jha},
  title  = {Guard Model Verdicts: per-item results for Qwen3Guard baselines and LoRA fine-tunes},
  year   = {2026},
  note   = {ORCID 0009-0004-3959-6099},
  howpublished = {\url{https://huggingface.co/datasets/invincible-jha/guard-verdicts}}
}
```
