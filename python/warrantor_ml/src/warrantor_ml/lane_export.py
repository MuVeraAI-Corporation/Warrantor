"""Render the standalone Kaggle and Modal runners from a recipe, rather than hand-writing them.

``ml/README.md`` states the rule this module exists to satisfy: ``tools/ci/run_python_checks.py``
discovers projects by globbing ``python/*/pyproject.toml``, so nothing under ``ml/`` is ever
linted, formatted or tested. Code that lives there is unverified, which is the anti-pattern
``rust/self-governance`` exists to name. A Modal entrypoint hand-written under ``ml/`` would be
the same mistake with a different filename.

So the lane scripts are *generated* from linted package code, the way ``deploy_model`` already
generates a Rust adapter from Python. The generator is inside the gate; its output is a file the
orchestrator uploads. Tests ``compile()`` the generated text and assert it retains the three
behaviours that must survive any edit to the template: no CPU fallback, the fp16 calibration
warning on the Kaggle lanes, and the gated-data message.

**Nothing here executes or dispatches anything.** :func:`render_modal_entrypoint` produces text
containing Modal decorators; it does not import ``modal``, does not authenticate, and does not
submit a job. Running it is the orchestrator's decision, not this module's.
"""

from __future__ import annotations

import json
from typing import Any

from ._canonical import canonical_json, sha256_text
from .lanes import LaneResolution
from .recipes import Recipe

__all__ = [
    "GATED_DATA_MESSAGE",
    "NO_CPU_FALLBACK_MESSAGE",
    "render_kaggle_script",
    "render_modal_entrypoint",
]

#: Must survive into every generated script. Asserted by a test, because the whole reason the
#: original Kaggle script says this is that a silent CPU fallback produces an artifact nobody
#: can tell apart from a real one until it is in front of a deny gate.
NO_CPU_FALLBACK_MESSAGE = (
    "FATAL: no CUDA device is available.\\n\\n"
    "This script has NO CPU fallback by design. A guard-model fine-tune that silently drops to "
    "CPU does not fail -- it appears to work, takes days, and produces an artifact "
    "indistinguishable from a real one until it is in front of a deny gate."
)

#: Also required in every generated script. Both corpora are gated behind auto-approved
#: click-through forms and there is no anonymous download path; a script that fails with a bare
#: HTTP 401 wastes a session on a problem whose fix is a manual human step.
GATED_DATA_MESSAGE = (
    "WildGuardMix and ExpGuardMix are GATED. Accept the form on the Hub and set HF_TOKEN, or "
    "attach the parquet as a dataset input. There is no anonymous download path."
)

#: Emitted on lanes with no bf16. A guard model's product is a calibrated logit and fp16 loss
#: scaling is exactly where calibration goes quietly wrong.
FP16_CALIBRATION_WARNING = (
    "WARNING: this lane has NO bf16. Qwen3Guard ships torch_dtype=bfloat16, so weights are cast "
    "to fp16 and training inherits fp16 loss-scaling behaviour. A guard model's product is a "
    "CALIBRATED LOGIT -- verify loss-scale stability on a short run before committing the "
    "weekly budget, and do not compare this adapter against a bf16-measured baseline."
)


def _run_manifest(recipe: Recipe, resolution: LaneResolution) -> dict[str, Any]:
    """The block every generated script writes beside its adapter.

    Carrying the recipe digest, the lane and the precision into the artifact is what lets the
    parity gate refuse a cross-lane comparison later. A run record that omits them describes a
    result nobody can place.
    """

    return {
        "recipe_id": recipe.recipe_id,
        "recipe_digest": recipe.recipe_digest,
        "lane": resolution.lane.key,
        "precision": resolution.precision,
        "precision_reason": resolution.precision_reason,
        "estimated_vram_gib": resolution.estimated_vram_gib,
        "estimated_hours": resolution.estimated_hours,
        "save_steps": resolution.save_steps,
        "warnings": list(resolution.warnings),
    }


def _shared_preamble(recipe: Recipe, resolution: LaneResolution) -> str:
    """The header, the refusals and the run manifest, shared by both lane templates."""

    lane = resolution.lane
    manifest = json.dumps(_run_manifest(recipe, resolution), indent=4)
    fp16_block = f'print("""{FP16_CALIBRATION_WARNING}""")\n' if not lane.supports_bf16 else ""
    return f'''#!/usr/bin/env python3
"""GENERATED -- do not edit. Rendered by warrantor_ml.lane_export from recipe
{recipe.recipe_id!r} for lane {lane.key!r}.

Edit the recipe in python/warrantor_ml/src/warrantor_ml/recipes.py and regenerate. This file is
deliberately standalone: the lane does not have this repository checked out, so it imports
nothing from warrantor_ml. It is generated rather than hand-written because code under ml/ is
never discovered by tools/ci/run_python_checks.py -- no ruff, no pytest -- and an ungoverned
code surface inside a governance substrate is the anti-pattern rust/self-governance names.

Recipe digest: {recipe.recipe_digest}
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RUN_MANIFEST = {manifest}

BASE_REPO = "{recipe.config.profile().repo_id}"
TARGET_MODULES = {list(recipe.config.profile().target_modules)!r}
SEQUENCE_LENGTH = {recipe.config.sequence_length}
BATCH_SIZE = {recipe.config.batch_size}
GRAD_ACCUM = {recipe.config.gradient_accumulation_steps}
LEARNING_RATE = {recipe.config.learning_rate}
EPOCHS = {recipe.config.epochs}
LORA_RANK = {recipe.config.lora_rank}
LORA_ALPHA = {recipe.config.lora_alpha}
SEED = {recipe.config.seed}
SAVE_STEPS = {resolution.save_steps!r}
PRECISION = "{resolution.precision}"

NO_GPU_MESSAGE = """{NO_CPU_FALLBACK_MESSAGE}"""

GATED_DATA_MESSAGE = """{GATED_DATA_MESSAGE}"""


def require_cuda() -> None:
    """Abort loudly without a GPU. There is no CPU fallback and there will not be one."""

    import torch

    if not torch.cuda.is_available():
        print(NO_GPU_MESSAGE, file=sys.stderr)
        raise SystemExit(2)


def load_pairs(path: Path) -> list[dict]:
    """Read the JSONL corpus this recipe was built for."""

    if not path.exists():
        print(GATED_DATA_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    if not rows:
        print(GATED_DATA_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    return rows


{fp16_block}'''


def _training_body() -> str:
    """The training call, identical on both lanes so a lane cannot change the arithmetic."""

    return '''
def train(corpus: Path, output_dir: Path, resume_from: str | None) -> Path:
    """Run the fine-tune. Requires CUDA; writes the adapter, tokenizer and run record."""

    require_cuda()
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        Trainer,
        TrainingArguments,
    )

    torch.manual_seed(SEED)
    compute_dtype = torch.bfloat16 if PRECISION == "bf16" else torch.float16

    tokenizer = AutoTokenizer.from_pretrained(BASE_REPO, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    load_kwargs = {"dtype": compute_dtype, "device_map": {"": 0}}
    if RUN_MANIFEST["recipe_id"].startswith("guard-4b"):
        load_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute_dtype,
        )
    model = AutoModelForCausalLM.from_pretrained(BASE_REPO, **load_kwargs)
    if "quantization_config" in load_kwargs:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    model = get_peft_model(
        model,
        LoraConfig(
            r=LORA_RANK,
            lora_alpha=LORA_ALPHA,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=TARGET_MODULES,
        ),
    )
    model.gradient_checkpointing_enable()

    pairs = load_pairs(corpus)
    dataset = Dataset.from_list(
        [{"text": row["prompt"] + "\\n" + row["target"]} for row in pairs]
    )
    tokenized = dataset.map(
        lambda batch: tokenizer(
            batch["text"], truncation=True, max_length=SEQUENCE_LENGTH, padding="max_length"
        ),
        batched=True,
        remove_columns=["text"],
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    arguments = TrainingArguments(
        output_dir=str(output_dir),
        per_device_train_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM,
        num_train_epochs=EPOCHS,
        learning_rate=LEARNING_RATE,
        logging_steps=10,
        # A session that is killed at the cap must resume rather than restart. SAVE_STEPS is
        # computed by warrantor_ml.lanes from the lane's session cap, not guessed here.
        save_strategy="steps" if SAVE_STEPS else "epoch",
        save_steps=SAVE_STEPS or 500,
        seed=SEED,
        data_seed=SEED,
        bf16=PRECISION == "bf16",
        fp16=PRECISION == "fp16",
        gradient_checkpointing=True,
        report_to=[],
    )
    trainer = Trainer(model=model, args=arguments, train_dataset=tokenized)
    trainer.train(resume_from_checkpoint=resume_from)
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    record = dict(RUN_MANIFEST)
    record["rows_trained"] = len(pairs)
    (output_dir / "run_record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return output_dir


def build_parser() -> argparse.ArgumentParser:
    """CLI for the generated runner."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="JSONL corpus for this recipe")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--resume-from",
        help="checkpoint directory to resume from after a session was killed at the cap",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    return parser
'''


def render_kaggle_script(recipe: Recipe, resolution: LaneResolution) -> str:
    """Render the standalone Kaggle notebook script for a recipe.

    Kaggle sessions are killed at 12 hours, so the generated script always takes
    ``--resume-from`` and always writes checkpoints at the interval
    :func:`warrantor_ml.lanes.resolve` computed. That is the difference between a killed session
    costing an hour and costing the week's budget.
    """

    if not resolution.lane.key.startswith("kaggle"):
        raise ValueError(
            f"render_kaggle_script was given lane {resolution.lane.key!r}. Resolve the recipe "
            "against a kaggle lane first -- the session cap and the precision differ, and a "
            "script that claims the wrong lane produces a run record that lies about it."
        )
    return (
        _shared_preamble(recipe, resolution)
        + _training_body()
        + '''

def main(argv: list[str] | None = None) -> int:
    """Entry point. On Kaggle: Settings -> Accelerator -> GPU T4 x2 or P100, then run."""

    arguments = build_parser().parse_args(argv)
    print(json.dumps(RUN_MANIFEST, indent=2))
    if arguments.dry_run:
        print("PLAN ONLY -- no GPU was touched and no training was performed.")
        return 0
    written = train(arguments.corpus, arguments.output_dir, arguments.resume_from)
    print(f"adapter: {written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    )


def render_modal_entrypoint(recipe: Recipe, resolution: LaneResolution) -> str:
    """Render the Modal entrypoint for a recipe. Produces text; dispatches nothing.

    The generated file declares a Modal app and a GPU function. This module does not import
    ``modal`` -- it is an optional extra and CI does not install it -- and calling
    ``modal run`` is the orchestrator's decision.
    """

    lane = resolution.lane
    if lane.key != "modal-a100":
        raise ValueError(
            f"render_modal_entrypoint was given lane {lane.key!r}; resolve against modal-a100."
        )
    return (
        _shared_preamble(recipe, resolution)
        + _training_body()
        + f'''

# Modal wiring. Declaring an app is not running one: this file is uploaded by the orchestrator
# and invoked with `modal run`. Nothing in warrantor_ml dispatches it.
try:
    import modal
except ImportError:  # pragma: no cover - modal is an optional extra, never in `dev`
    modal = None

if modal is not None:
    IMAGE = modal.Image.debian_slim().pip_install(
        "torch>=2.7", "transformers>=4.51", "datasets>=2.19", "peft>=0.11", "accelerate>=0.30"
    )
    APP = modal.App("warrantor-{recipe.recipe_id}")

    @APP.function(image=IMAGE, gpu="A100-80GB", timeout=60 * 60 * 8)
    def train_remote(corpus_bytes: bytes) -> dict:
        """Train on a Modal A100 and return the run record.

        The corpus travels as bytes rather than being downloaded inside the container: both
        corpora are gated, and a container that authenticates to the Hub is a container holding
        a read token.
        """

        corpus = Path("/tmp/corpus.jsonl")
        corpus.write_bytes(corpus_bytes)
        output = Path("/tmp/adapter")
        train(corpus, output, None)
        return json.loads((output / "run_record.json").read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    """Local entry point -- runs the same training body without Modal."""

    arguments = build_parser().parse_args(argv)
    print(json.dumps(RUN_MANIFEST, indent=2))
    if arguments.dry_run:
        print("PLAN ONLY -- no GPU was touched and no training was performed.")
        return 0
    written = train(arguments.corpus, arguments.output_dir, arguments.resume_from)
    print(f"adapter: {{written}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    )


def script_digest(text: str) -> str:
    """Digest of a generated script, so a run record can pin the exact file that ran."""

    return sha256_text(canonical_json({"script": text}))
