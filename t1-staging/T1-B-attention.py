#!/usr/bin/env python3
"""GENERATED -- do not edit. Rendered by warrantor_ml.lane_export from recipe
'guard-0.6b-expguard-weak@T1-B-attention' for lane 'modal-a100'.

Edit the recipe in python/warrantor_ml/src/warrantor_ml/recipes.py and regenerate. This file is
deliberately standalone: the lane does not have this repository checked out, so it imports
nothing from warrantor_ml. It is generated rather than hand-written because code under ml/ is
never discovered by tools/ci/run_python_checks.py -- no ruff, no pytest -- and an ungoverned
code surface inside a governance substrate is the anti-pattern rust/self-governance names.

Recipe digest: sha256:70851d9de985417c48a54f89bc43eb0fed1994ef2f7eeca490e46affe3aebc1a
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Embedded as JSON and parsed at import rather than pasted in as a Python literal. `json.dumps`
# emits `null`, `true` and `false`, which are not Python names: the modal-a100 lane resolves
# save_steps to None, so the template that inlined this produced an entrypoint that compile()d
# cleanly and then died with `NameError: name 'null' is not defined` the moment it was imported.
# A test that only compiles the text cannot see that; one that executes it can.
RUN_MANIFEST = json.loads(
    """{
    "recipe_id": "guard-0.6b-expguard-weak@T1-B-attention",
    "recipe_digest": "sha256:70851d9de985417c48a54f89bc43eb0fed1994ef2f7eeca490e46affe3aebc1a",
    "lane": "modal-a100",
    "precision": "bf16",
    "precision_reason": "sm_8x supports bf16 natively; matching the base model's dtype.",
    "estimated_vram_gib": 6.146,
    "estimated_hours": 1.78,
    "save_steps": 70,
    "warnings": [
        "LoRA over an unquantised base leaves very little margin on a 16 GB card and will OOM when the desktop compositor spikes. Prefer technique=qlora locally.",
        "expguardmix is GATED on Hugging Face. Accept the form and export a read token before this run, or the data step fails with HTTP 401. Run `warrantor-ml-datasets --preflight` first.",
        "ExpGuardMix's gate form requires affirming research-only use, which is NARROWER than its CC-BY-4.0 licence. Do not train a commercially shipped pack on it without a written read from counsel."
    ]
}"""
)

BASE_REPO = "Qwen/Qwen3Guard-Gen-0.6B"
TARGET_MODULES = ['q_proj', 'k_proj', 'v_proj', 'o_proj']
SEQUENCE_LENGTH = 2048
BATCH_SIZE = 2
GRAD_ACCUM = 8
LEARNING_RATE = 0.0001
EPOCHS = 1.0
LORA_RANK = 16
LORA_ALPHA = 32
SEED = 20260813
SAVE_STEPS = 70
PRECISION = "bf16"
SUPERVISE_SEVERITY = True

NO_GPU_MESSAGE = """FATAL: no CUDA device is available.\n\nThis script has NO CPU fallback by design. A guard-model fine-tune that silently drops to CPU does not fail -- it appears to work, takes days, and produces an artifact indistinguishable from a real one until it is in front of a deny gate."""

GATED_DATA_MESSAGE = """WildGuardMix and ExpGuardMix are GATED. Accept the form on the Hub and set HF_TOKEN, or attach the parquet as a dataset input. There is no anonymous download path."""

NO_TRAINABLE_ROWS_MESSAGE = """FATAL: tokenising the corpus produced no trainable rows.\n\nEvery row was dropped -- either the corpus is not in the {prompt, target} shape this recipe was built for, or every target overflowed SEQUENCE_LENGTH. Training zero rows would save an UNTRAINED adapter that looks exactly like a trained one. Check the corpus with `warrantor-ml-build-corpus --describe-only` before spending the session again."""


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



#: Positions the loss ignores. Any value torch's cross-entropy treats as "skip"; -100 is the
#: convention every transformers example uses and the one the Trainer expects.
LABEL_MASK = -100


def build_training_rows(pairs: list[dict], tokenizer) -> list[dict]:
    """Tokenize prompt+target into input_ids / attention_mask / LABELS.

    Three failures this prevents, in the order they used to bite:

    1. **No labels at all.** Handing `Trainer` a dataset of input_ids and attention_mask with no
       `labels` column and no data collator makes a causal LM return no loss, and Trainer aborts
       with "The model did not return a loss" -- at step 0, after the model has been downloaded
       and quantised. On Kaggle that is a session out of a 30-hour weekly budget for nothing.
    2. **Training on the prompt.** Labels that copy the whole sequence teach the adapter to
       reproduce the attack text as well as the verdict. The prompt is masked with LABEL_MASK so
       the loss is computed on the `Safety:` / `Categories:` answer only, which is the thing the
       benchmark parser reads.
    3. **Truncating into the verdict.** A row longer than SEQUENCE_LENGTH is trimmed from the
       LEFT of the prompt, never the right of the target. Cutting the target teaches the adapter
       to emit a half-verdict, and a half-verdict parses as neither safe nor unsafe.

    Padding is NOT done here. Every row keeps its own length and `pad_batch` pads each batch to
    its own longest row: padding every row to 2048 would spend most of the session's compute on
    pad tokens.
    """

    eos = getattr(tokenizer, "eos_token_id", None)
    rows = []
    for pair in pairs:
        prompt_ids = list(tokenizer(pair["prompt"] + "\n", add_special_tokens=False)["input_ids"])
        target_ids = list(tokenizer(pair["target"], add_special_tokens=False)["input_ids"])
        if eos is not None:
            target_ids = target_ids + [eos]
        if not target_ids:
            continue

        # How much of the target the loss covers. With SUPERVISE_SEVERITY off, the `Safety:` line
        # is generated but never learned: it stays in input_ids so the `Categories:` line is still
        # conditioned on it, and is masked in labels so no gradient teaches the model to emit it.
        # Tokenising the severity line separately -- rather than counting characters -- because a
        # BPE token can straddle the newline and a character offset would mask a partial token.
        supervised_from = 0
        if not SUPERVISE_SEVERITY:
            severity_line, _, _ = pair["target"].partition("\n")
            supervised_from = len(
                tokenizer(severity_line + "\n", add_special_tokens=False)["input_ids"]
            )
            # Drop a row whose target is severity and nothing else. The comparison allows for the
            # appended eos: supervising only "stop here" is not a training signal, and an
            # effectively-blank row silently shrinks the corpus while still being counted in it.
            meaningful = len(target_ids) - (1 if eos is not None else 0)
            if supervised_from >= meaningful:
                continue
        overflow = len(prompt_ids) + len(target_ids) - SEQUENCE_LENGTH
        if overflow > 0:
            if overflow >= len(prompt_ids):
                # The target alone does not fit. Drop the row rather than train on a fragment of
                # a verdict -- a corpus is allowed to lose a row, a label format is not.
                continue
            prompt_ids = prompt_ids[overflow:]
        input_ids = prompt_ids + target_ids
        rows.append(
            {
                "input_ids": input_ids,
                "attention_mask": [1] * len(input_ids),
                "labels": [LABEL_MASK] * (len(prompt_ids) + supervised_from)
                + target_ids[supervised_from:],
            }
        )
    return rows


def pad_batch(features: list[dict], pad_token_id: int) -> dict:
    """Right-pad one batch to its longest row. Pure Python; returns lists, not tensors.

    Label padding is LABEL_MASK and never `pad_token_id`: a pad token in the labels is a token
    the model is trained to emit, and the model would learn to end every verdict in padding.
    Attention-mask padding is 0 so the padded positions are not attended to either.
    """

    width = max(len(feature["input_ids"]) for feature in features)
    batch = {"input_ids": [], "attention_mask": [], "labels": []}
    for feature in features:
        gap = width - len(feature["input_ids"])
        batch["input_ids"].append(list(feature["input_ids"]) + [pad_token_id] * gap)
        batch["attention_mask"].append(list(feature["attention_mask"]) + [0] * gap)
        batch["labels"].append(list(feature["labels"]) + [LABEL_MASK] * gap)
    return batch


def make_collator(pad_token_id: int):
    """The Trainer data collator. Tensor conversion is the only torch in the data path."""

    def collate(features: list[dict]) -> dict:
        import torch

        padded = pad_batch(features, pad_token_id)
        return {key: torch.tensor(value, dtype=torch.long) for key, value in padded.items()}

    return collate


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
    rows = build_training_rows(pairs, tokenizer)
    if not rows:
        print(NO_TRAINABLE_ROWS_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    dataset = Dataset.from_list(rows)

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
    # data_collator is not optional. Without one the default collator emits input_ids and
    # attention_mask only, a causal LM returns no loss, and Trainer raises "The model did not
    # return a loss" at step 0 -- after the download and the quantisation, with the session
    # already spent. The hand-written ml/kaggle/train_guard_lora.py passes a collator for this
    # exact reason; the generated template used to be the one that did not.
    pad_token_id = tokenizer.pad_token_id
    if pad_token_id is None:
        pad_token_id = tokenizer.eos_token_id
    trainer = Trainer(
        model=model,
        args=arguments,
        train_dataset=dataset,
        data_collator=make_collator(pad_token_id),
    )
    trainer.train(resume_from_checkpoint=resume_from)
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    record = dict(RUN_MANIFEST)
    record["rows_read"] = len(pairs)
    record["rows_trained"] = len(rows)
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


# Modal wiring. Declaring an app is not running one: this file is uploaded by the orchestrator
# and invoked with `modal run`. Nothing in warrantor_ml dispatches it.
try:
    import modal
except ImportError:  # pragma: no cover - modal is an optional extra, never in `dev`
    modal = None

if modal is not None:
    # The recipe's own `train` extra, mirrored package-for-package. bitsandbytes was missing
    # from this list until the first 4B Modal dispatch died inside the container with
    # `ImportError: Using bitsandbytes 4-bit quantization requires bitsandbytes` -- the 0.6B
    # recipes (plain bf16 LoRA) never tripped it, so the gap survived until a qlora recipe
    # actually shipped to the lane. An image that installs less than the recipes require is a
    # lane the router can approve and the first step cannot run.
    IMAGE = modal.Image.debian_slim().pip_install(
        "torch>=2.7",
        "transformers>=4.51",
        "datasets>=2.19",
        "peft>=0.11",
        "accelerate>=0.30",
        "trl>=0.9",
        "bitsandbytes>=0.46.1",
    )
    APP = modal.App("warrantor-guard-0.6b-expguard-weak@T1-B-attention")

    # The adapter outlives the container or the run bought nothing. A Modal function's
    # filesystem is ephemeral: writing weights to /tmp and returning a run record produces a
    # SUCCESS-SHAPED result -- rows_trained, a valid manifest, exit 0 -- with no model behind
    # it. That is the failure this substrate exists to refuse, so the weights go to a named
    # Volume and the function refuses to report success until it has read them back.
    ADAPTER_VOLUME = modal.Volume.from_name(
        "warrantor-adapters", create_if_missing=True
    )
    ADAPTER_ROOT = Path("/adapters")

    @APP.function(
        image=IMAGE,
        gpu="A100-80GB",
        timeout=60 * 60 * 8,
        volumes={str(ADAPTER_ROOT): ADAPTER_VOLUME},
    )
    def train_remote(corpus_bytes: bytes, run_id: str) -> dict:
        """Train on a Modal A100, persist the adapter, and return the run record.

        The corpus travels as bytes rather than being downloaded inside the container: both
        corpora are gated, and a container that authenticates to the Hub is a container holding
        a read token.

        ``run_id`` names the Volume subdirectory. It is required rather than defaulted so two
        runs of the same recipe cannot silently overwrite each other's weights -- an adapter
        that was replaced by a later run is indistinguishable from one that trained badly.
        """

        corpus = Path("/tmp/corpus.jsonl")
        corpus.write_bytes(corpus_bytes)
        output = ADAPTER_ROOT / "guard-0.6b-expguard-weak@T1-B-attention" / run_id
        # Refuse only when the directory holds a COMPLETED run (run_record.json is written
        # after training, weight verification and volume commit). A bare directory is the
        # residue of an interrupted attempt -- a preempted container, which Modal restarts
        # with the same input -- and refusing on that turned every preemption into a dead
        # app: the restart collided with its own partial directory and exited, costing the
        # whole session's GPU time. There are no mid-epoch checkpoints, so the correct
        # behaviour on restart is to train from scratch over the residue, which is what
        # this now allows.
        if (output / "run_record.json").exists():
            raise SystemExit(
                f"refusing to train: {output} holds a completed run. Pick a new "
                "run_id rather than overwriting an adapter whose evaluation may already be "
                "recorded against its digest."
            )
        train(corpus, output, None)

        # Commit, then read back. commit() is what makes the writes durable outside this
        # container; without it the volume is unchanged and every check below still passes
        # against the container's own view of the filesystem.
        ADAPTER_VOLUME.commit()
        weights = sorted(output.glob("adapter_model.*"))
        if not weights:
            raise SystemExit(
                f"trained, but no adapter weights are present at {output} after commit. "
                "The run record would otherwise report success for a session that produced "
                "no model."
            )

        record = json.loads((output / "run_record.json").read_text(encoding="utf-8"))
        record["adapter_volume"] = "warrantor-adapters"
        record["adapter_path"] = str(output.relative_to(ADAPTER_ROOT))
        record["adapter_bytes"] = sum(item.stat().st_size for item in weights)
        return record

    @APP.local_entrypoint()
    def dispatch(corpus: str, run_id: str, record_out: str = "") -> None:
        """Send the corpus to the GPU function and write the returned record locally.

        Invoked as::

            modal run <this file>::dispatch --corpus corpora/weak.jsonl --run-id 2026-08-13a

        Without this the module declares a GPU function nobody can reach: `modal run` on the
        file alone has no way to hand a `bytes` argument to `train_remote`, so the runner was
        dispatchable only in the comment that said it was.

        The record is written to disk as well as printed. It carries the volume path the
        adapter landed at, and that is the only pointer back to six hours of GPU time.
        """

        corpus_path = Path(corpus)
        if not corpus_path.is_file():
            raise SystemExit(f"no corpus at {corpus_path} -- build it before dispatching a run.")

        record = train_remote.remote(corpus_path.read_bytes(), run_id)
        text = json.dumps(record, indent=2)
        print(text)
        destination = Path(record_out) if record_out else corpus_path.with_name(
            f"run_record_{run_id}.json"
        )
        destination.write_text(text + "\n", encoding="utf-8")
        print(f"run record: {destination}")


def main(argv: list[str] | None = None) -> int:
    """Local entry point -- runs the same training body without Modal."""

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
