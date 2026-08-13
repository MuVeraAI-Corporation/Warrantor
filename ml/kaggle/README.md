# Kaggle run — exactly what to upload and what to bring back

The training tier is Kaggle's free GPU quota: **30 GPU-hours/week** (2× T4 or P100) and
**20 TPU-hours/week**. Nothing in this directory spends money, and nothing in it should ever be
changed so that it does. If a run does not fit the free quota, the answer is a smaller run.

---

## Before you touch Kaggle: the manual unblock

**Both training corpora are gated and both return HTTP 401 to anonymous requests.** This is not
a code problem and no script can work around it.

| Corpus | Repo | Gate | Licence | Commercial use |
| --- | --- | --- | --- | --- |
| WildGuardMix | `allenai/wildguardmix` | `auto` | ODC-By-1.0 | Restricted by AI2 responsible-use click-through |
| ExpGuardMix | `6rightjade/expguardmix` | `auto` | CC-BY-4.0 | **Unresolved** — the gate form says research-only |

`auto` means the request is approved the instant the form is submitted — no reviewer, no
waiting. It still needs a logged-in account, an accepted form, and a read token. Five minutes,
zero cost, and it cannot be scripted.

1. Sign in to Hugging Face, open each dataset page, accept the form.
2. Create a **read** token at <https://huggingface.co/settings/tokens>.
3. Check locally before you get to Kaggle:

   ```bash
   HF_TOKEN=hf_... python ml/datasets.py --preflight
   ```

> **Legal, unresolved, do not skip.** ExpGuardMix's licence is CC-BY-4.0, which permits
> commercial use. The gate form you must accept to obtain the file says *"solely for research
> purposes"*. The click-through is the agreement that was actually signed and it is narrower
> than the licence. Training a commercially shipped finance/healthcare/law pack on ExpGuardMix
> is **not** cleared by "it's CC-BY". Get a written read from counsel first — discovering this
> after training costs far more than discovering it now.

---

## What to upload

Two things, and only two.

### 1. The data, as a private Kaggle Dataset

Download the parquet locally (with your token), then upload it as a **private** Kaggle Dataset.
Do not make it public: neither licence grants you redistribution rights you can pass on, and
ODC-By governs the database rather than the underlying content.

| File | Size | Rows |
| --- | --- | --- |
| `wildguard_train.parquet` | 53.7 MB | 86,759 |
| `wildguard_test.parquet` | 2.3 MB | 1,725 |
| `expguardtrain.parquet` | 20.9 MB | 56,653 |
| `expguardtest.parquet` | 1.5 MB | 2,275 |

Both corpora are tiny — under 80 MB combined. Upload time is not the constraint; the gate is.

> **Row-count correction:** WildGuardMix is **88,484 rows total**, not the 92K figure that
> circulated in early planning. Use 88,484 in every public claim, licence document and AIBOM.

### 2. `train_guard_lora.py`

Upload it as the notebook/script body, or attach it as a Dataset and `%run` it. It is
deliberately self-contained — it imports nothing from this repository, so there is no
`pip install` step and no path wiring.

---

## Notebook settings

| Setting | Value | Why |
| --- | --- | --- |
| Accelerator | **GPU T4 ×2** | 32 GB aggregate. P100 also works and is slower. |
| Internet | On only if pulling from the Hub | Off is safer; prefer the attached Dataset. |
| Persistence | Files only | `/kaggle/working` is what you download. |
| Secrets | `HF_TOKEN` (only if Internet is on) | Never paste a token into a cell. |

---

## Run it

```bash
python train_guard_lora.py \
    --train-parquet /kaggle/input/wildguardmix/wildguard_train.parquet \
    --output-dir /kaggle/working/guard-lora \
    --max-samples 20000 \
    --sequence-length 1024 \
    --batch-size 1 \
    --grad-accum 16
```

Start with `--max-samples 2000` and one logging interval to confirm the loss moves and the
memory holds. A run that OOMs at hour three has cost three of thirty weekly hours.

### The precision trap, stated once

Kaggle's free GPUs are **T4 (sm_75)** and **P100 (sm_60)**. **Neither supports bf16**, and
neither supports FlashAttention-2. Qwen3Guard ships `torch_dtype: bfloat16`, so the run casts to
fp16 and inherits fp16 loss-scaling behaviour.

That matters more here than it would elsewhere. A guard model's entire product is a *calibrated
logit*, and logit calibration is exactly what fp16 loss scaling perturbs. The script prints the
warning at startup. Watch the loss scale in the first hundred steps before committing hours to
a configuration.

---

## What to bring back

Download `/kaggle/working/guard-lora`:

| Artifact | What it is |
| --- | --- |
| `adapter_model.safetensors` | The LoRA adapter — tens of MB, not gigabytes |
| `adapter_config.json` | Rank, alpha, target modules, base model reference |
| `tokenizer.json`, `tokenizer_config.json`, `special_tokens_map.json` | The tokenizer as used |
| `run_record.json` | Device facts, precision and why, dataset digest, hyperparameters, train metrics |

**Do not bring back merged base weights.** The adapter plus a pinned base revision is the
reproducible artifact; a merged 8 GB blob is neither reproducible nor a sensible thing to move
through a browser download.

**Do not commit any of it.** `.gitignore` covers `*.safetensors`, `*.gguf`, `*.bin`, `*.pt`,
`checkpoints/` and `ml/data/` for this reason.

---

## What happens next, in order

1. **Evaluate. Recall first.**

   ```bash
   python ml/evaluate.py \
       --eval-set eval/wildguard_test.jsonl \
       --backend ollama \
       --out evidence/ml/eval-guard-lora.json
   ```

   `evidence/` is git-ignored and is where CI writes gate evidence, so results belong there.

2. **Beat the baseline or bin the run.** For the injection lane the zero-training-cost baseline
   is `protectai/deberta-v3-base-prompt-injection-v2`. If the fine-tune does not beat it, the
   Kaggle hours were not worth spending and the honest move is to say so.

3. **Fill the AIBOM.** `ml/model_card.py` will refuse to emit a card with a missing required
   field, and several of those fields can only be filled from `run_record.json`:
   training energy and region, the dataset digest, the hyperparameters, the compute tier.

4. **Register the scanner.** `ml/deploy_model.py` binds the adapter behind `ContentScanner`
   without touching enforcement code.

---

## Routing, so nobody re-derives it

| Lane | Where | Why |
| --- | --- | --- |
| DeBERTa-v3-large injection, **full** fine-tune | **Local** (16 GB card) | ~10 GiB at batch 16 / seq 512. The only full fine-tune in the plan that fits anywhere free. Do this one first. |
| Qwen3Guard-Gen-4B QLoRA | **Local** | NF4 base + r=16 at seq 2048 ≈ 8 GiB. |
| Qwen3Guard-Gen-8B LoRA | **Kaggle** | bf16 weights alone are 15.25 GiB — more than a 16 GB card's free VRAM before any KV cache. |
| Any Qwen3Guard **full** fine-tune | **Nowhere free** | 4B full FT needs ~48–64 GiB. Kaggle's 32 GB aggregate is not enough. That is an A100-80GB job. |

`python ml/fine_tune.py --dry-run` prints the VRAM estimate for any configuration without
touching a GPU.
