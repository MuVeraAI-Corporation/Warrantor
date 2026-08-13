# warrantor-ml

Model intelligence for the W10 content-moderation plane: the guard-model dataset registry,
recall-first evaluation, the signed AIBOM, LoRA/QLoRA training, and `ContentScanner`
registration.

This is the gated implementation. The operator-facing entry points and the full narrative —
model choices and the recall numbers behind them, the zero-spend rule, and how to run each
piece — live in [`ml/README.md`](../../ml/README.md).

## Install

```bash
pip install -e .[dev]          # what CI installs
pip install -e .[train,hub]    # torch / transformers / peft / datasets, for actual training
```

`torch` and friends are deliberately **not** in the `dev` extra. `tools/ci/run_python_checks.py`
installs only `dev`, and pulling a multi-gigabyte CUDA stack into every CI run to satisfy one
project would cost far more than it proves. Every test in this project runs without them.

## Modules

| Module | Responsibility |
| --- | --- |
| `datasets` | Declarative corpus registry — licence, click-through terms, gating, cache paths. Downloads on demand, never at import. |
| `metrics` | Confusion matrix and the derived rates. Recall first, accuracy last. |
| `evaluate` | Runs a guard model over a labelled set via a local Ollama backend. Deterministic given a seed; writes a digest-bound JSON result. |
| `model_card` | Builds and Ed25519-signs an AIBOM. Refuses to emit one with a missing required field. |
| `fine_tune` | LoRA/QLoRA planning and training. Pure VRAM arithmetic; no CPU fallback. |
| `deploy_model` | Binds a fine-tuned adapter behind `ContentScanner` without touching enforcement code. |

## Test

```bash
PYTHONPATH=src python -m pytest tests -q
python -m ruff check src tests && python -m ruff format --check src tests
```

No test requires a GPU, a network connection, or Hugging Face credentials.
