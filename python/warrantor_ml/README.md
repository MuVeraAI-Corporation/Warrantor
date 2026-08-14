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
| `benchmark_wildguard` | The held-out WildGuardTest split, broken down adversarial versus plain. |
| `benchmark_expguard` | The held-out ExpGuardTest split, broken down by vertical domain. |

### The training programme (RFC W2)

| Module | Responsibility |
| --- | --- |
| `stats` | Wilson intervals, two-proportion z, and a two-sided improvement verdict. One arithmetic, shared by the vertical benchmark and the parity gate. |
| `manifest` | Dataset provenance. A validator that **refuses** five named conditions, not a schema that records them. |
| `teachers` | Open-weight teachers may generate; frontier judges may only score. Enforced by type: `JudgeScore` is not a row type. |
| `baselines` | The measured numbers from `ml/README.md`, frozen as counts with the backend configuration that produced them. |
| `leakage` | Normalised-content overlap between a training corpus and an eval split. The augmentation leak, not the published split boundary. |
| `lanes` | RTX 5080 / Kaggle T4-P100 / Modal A100. Refuses a run that will not fit or will not finish. |
| `recipes` | The nine recipes as data with a stable digest, so two lanes can run provably the same recipe. Also the only place a measured baseline becomes reachable: an unbound one cannot be gated against by any CLI. |
| `parity` | The blind gate. `promote` / `reject` / `insufficient_evidence`, two-sided and per-slice. |
| `lane_export` | Renders the standalone Kaggle and Modal runners from a recipe. Generates text; dispatches nothing. |
| `build_corpus` | Corpus CLI. `--describe-only` first, always. |
| `programme` | The recipes / lanes / export / parity CLIs. |
| `tasks.guard` | Models 1–4. One corpus builder, two selectors, targets pinned to `parse_guard_response`. |
| `tasks.bounds` | Model 5. Mirrors `WarrantBounds::contains`; scored on over-grant rate, never accuracy. |
| `tasks.triage` | Model 6. Labels from the operator's next grant, never from the served threshold. |
| `tasks.effects` | Model 7. Recall on the consequential set; a downgrade across that boundary is counted apart. |
| `tasks.summary` | Model 8. Accepts only a bundle the Rust verifier vouched for. |

## Test

```bash
PYTHONPATH=src python -m pytest tests -q
python -m ruff check src tests && python -m ruff format --check src tests
```

No test requires a GPU, a network connection, or Hugging Face credentials.
