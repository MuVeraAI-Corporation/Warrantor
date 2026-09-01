# T1 — does restricting LoRA target modules preserve the severity class?

**Status 2026-09-01: arm A dispatched on Modal. Arms B and C held pending its result.**

## The question

Every fine-tune in the programme damaged its severity field — two lost the
`controversial` class outright, two halved it while scoring *within noise* on
recall. The recipe notes blame shared weights: *"LoRA adapts q/k/v/o/gate/up/down
across every layer, weights BOTH output fields share."*

`lora_target_modules` was `None`, meaning all seven. T1 tests whether restricting
them preserves the class.

## The arms

| Arm | `TARGET_MODULES` | Recipe digest |
|---|---|---|
| **A — control** | all seven | `sha256:5a39936c…` |
| **B — attention** | `q_proj, k_proj, v_proj, o_proj` | `sha256:70851d9d…` |
| **C — MLP** | `gate_proj, up_proj, down_proj` | `sha256:bd14328c…` |

Everything else identical: `Qwen/Qwen3Guard-Gen-0.6B`, bf16, seed 20260813,
rank 16 / alpha 32, lr 1e-4, 1 epoch, `supervise_severity=True`, seq 2048,
batch 2, A100-80GB.

## Stop condition

**Arm A must reproduce the severity damage.** If it does not, the diagnosis is
wrong and B and C do not run.

## Corpus

`corpus-expguard-weak.jsonl` — 11,272 rows (5,636 positives + 5,636 benign at
`benign_ratio 1.0`), built from the recipe declaration against the cached
`expguardtrain.parquet`. All four target categories matched, none absent.
Manifest records `commercially_cleared: false` and GPT-4o upstream lineage.

## Evaluation path, pre-verified

1. `modal volume get warrantor-adapters …`
2. `warrantor-ml-publish --adapter … --base-snapshot M:/hf/hub/models--Qwen--Qwen3Guard-Gen-0.6B/snapshots/fada3b2f… --ollama-base hf.co/mradermacher/Qwen3Guard-Gen-0.6B-GGUF:Q4_K_M`
3. `python ml/run_corpus_benchmarks.py --model <new tag>`
4. `warrantor_ml.paired_analysis` against
   `eval_results/baseline-0.6b-2026-09-01/expguard-2026-09-01.json`

The baseline emits **122 `controversial`** on ExpGuardTest. That is the number
arm A is expected to collapse, and B and C are hoped to preserve.

## Two environment notes

- **`PYTHONIOENCODING=utf-8` is required** for `modal` on this machine. Without
  it the CLI dies with `'charmap' codec can't encode character '\u2713'` before
  dispatching anything — and the wrapper still reports exit 0, so the failure
  looks like a success. Check the log, not the exit code.
- The converter lives at `C:/Users/MuVeraAICorporation/.unsloth/llama.cpp/convert_lora_to_gguf.py`.
