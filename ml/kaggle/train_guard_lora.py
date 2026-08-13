#!/usr/bin/env python3
"""Standalone QLoRA/LoRA fine-tune of Qwen3Guard-Gen on the Kaggle free tier.

DELIBERATELY SELF-CONTAINED. Kaggle does not have this repository, so this script imports
nothing from ``warrantor_ml``. It duplicates a small amount of logic from
``python/warrantor_ml/src/warrantor_ml/fine_tune.py`` on purpose -- upload one file, run it,
bring back an adapter.

Hard behaviours:

* **No CPU fallback.** If there is no CUDA device the script exits non-zero with a message.
  A guard-model fine-tune that quietly runs on CPU produces an artifact nobody can tell apart
  from a real one.
* **fp16, not bf16, on the free tier.** Kaggle's GPUs are 2x T4 (sm_75) or P100 (sm_60) and
  neither has bf16. Qwen3Guard ships ``torch_dtype: bfloat16``, so the cast is forced and the
  script says so. Guard models are calibrated-logit products; watch the loss scale.
* **Gated data must already be attached.** WildGuardMix and ExpGuardMix are both gated behind
  auto-approved click-through forms. Attach the parquet as a Kaggle Dataset input, or set
  ``HF_TOKEN`` in Kaggle Secrets. There is no anonymous download path.
* **Zero marginal spend.** Kaggle's free quota only. Nothing here calls a paid API.

Usage on Kaggle (Settings -> Accelerator -> GPU T4 x2, Internet ON only if pulling from HF)::

    python train_guard_lora.py \\
        --train-parquet /kaggle/input/wildguardmix/wildguard_train.parquet \\
        --output-dir /kaggle/working/guard-lora \\
        --max-samples 20000

Bring back ``/kaggle/working/guard-lora`` -- adapter weights, tokenizer, ``run_record.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BASE_REPO = "Qwen/Qwen3Guard-Gen-4B"
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

SYSTEM_PROMPT = (
    "You are a safety classifier. Classify the user message and answer in exactly two lines:\n"
    "Safety: Safe|Unsafe|Controversial\n"
    "Categories: <comma-separated categories, or None>"
)

NO_GPU_MESSAGE = """\
FATAL: no CUDA device is available.

This script has NO CPU fallback by design. A guard-model fine-tune that silently drops to CPU
does not fail -- it appears to work, takes days, and produces an artifact indistinguishable
from a real one until it is in front of a deny gate.

On Kaggle: Notebook -> Settings -> Accelerator -> "GPU T4 x2" (or "GPU P100"), then restart the
session. Free quota is 30 GPU-hours/week.
"""


@dataclass
class Arguments:
    """Parsed CLI arguments."""

    train_parquet: Path
    output_dir: Path
    base_repo: str
    lora_rank: int
    lora_alpha: int
    lora_dropout: float
    sequence_length: int
    batch_size: int
    gradient_accumulation_steps: int
    learning_rate: float
    epochs: float
    seed: int
    max_samples: int | None
    four_bit: bool


def parse_arguments(argv: list[str] | None = None) -> Arguments:
    """Parse the command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-parquet", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("/kaggle/working/guard-lora"))
    parser.add_argument("--base-repo", default=BASE_REPO)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--sequence-length", type=int, default=1024)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=1e-4)
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=20260812)
    parser.add_argument("--max-samples", type=int)
    parser.add_argument(
        "--no-4bit",
        action="store_true",
        help="LoRA over an fp16 base instead of QLoRA. Needs device_map across both T4s.",
    )
    namespace = parser.parse_args(argv)
    return Arguments(
        train_parquet=namespace.train_parquet,
        output_dir=namespace.output_dir,
        base_repo=namespace.base_repo,
        lora_rank=namespace.lora_rank,
        lora_alpha=namespace.lora_alpha,
        lora_dropout=namespace.lora_dropout,
        sequence_length=namespace.sequence_length,
        batch_size=namespace.batch_size,
        gradient_accumulation_steps=namespace.grad_accum,
        learning_rate=namespace.learning_rate,
        epochs=namespace.epochs,
        seed=namespace.seed,
        max_samples=namespace.max_samples,
        four_bit=not namespace.no_4bit,
    )


def require_gpu() -> dict[str, Any]:
    """Return device facts, or exit loudly. No silent CPU fallback."""

    try:
        import torch
    except ImportError:
        print("FATAL: torch is not installed in this kernel.", file=sys.stderr)
        raise SystemExit(2) from None
    if not torch.cuda.is_available():
        print(NO_GPU_MESSAGE, file=sys.stderr)
        raise SystemExit(2)
    properties = torch.cuda.get_device_properties(0)
    free_bytes, total_bytes = torch.cuda.mem_get_info(0)
    facts = {
        "name": properties.name,
        "compute_capability": [properties.major, properties.minor],
        "device_count": torch.cuda.device_count(),
        "total_gib": round(total_bytes / 1024**3, 2),
        "free_gib": round(free_bytes / 1024**3, 2),
        "torch": torch.__version__,
        "supports_bf16": properties.major >= 8,
    }
    print(json.dumps(facts, indent=2))
    if not facts["supports_bf16"]:
        print(
            "\nNOTE: sm_%d%d has NO bf16 support. Qwen3Guard ships torch_dtype=bfloat16, so "
            "weights are cast to fp16 and this run inherits fp16 loss-scaling behaviour. A "
            "guard model's product is a calibrated logit -- watch the loss scale in the logs "
            "before committing 30 weekly hours to this configuration.\n"
            % (properties.major, properties.minor),
            file=sys.stderr,
        )
    return facts


def sha256_file(path: Path) -> str:
    """Stream a SHA-256 over a file so a multi-GB parquet fits in memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _harm_label_to_severity(value: Any) -> str:
    """Map a WildGuardMix harm label to a Qwen3Guard severity token."""

    text = str(value).strip().lower()
    if text in {"harmful", "unsafe", "true", "1"}:
        return "Unsafe"
    return "Safe"


def build_guard_example(row: dict[str, Any]) -> dict[str, str]:
    """Render one WildGuardMix row as a guard-format supervised example.

    WildGuardMix carries ``prompt``, ``prompt_harm_label``, ``response``,
    ``response_harm_label``, ``response_refusal_label``, ``adversarial`` and ``subcategory``.
    The target is the two-line format the evaluator parses, so training output and evaluation
    parsing cannot drift apart.
    """

    prompt = str(row.get("prompt") or "")
    severity = _harm_label_to_severity(row.get("prompt_harm_label"))
    categories: list[str] = []
    subcategory = row.get("subcategory")
    if subcategory:
        categories.append(str(subcategory).strip())
    if row.get("adversarial") in {True, "True", "true", 1}:
        categories.append("Jailbreak")
    category_line = ", ".join(categories) if categories else "None"
    return {
        "prompt": prompt,
        "target": f"Safety: {severity}\nCategories: {category_line}",
    }


def main(argv: list[str] | None = None) -> int:
    """Run the fine-tune."""

    arguments = parse_arguments(argv)
    device_facts = require_gpu()

    import torch
    from datasets import load_dataset
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    torch.manual_seed(arguments.seed)
    compute_dtype = torch.bfloat16 if device_facts["supports_bf16"] else torch.float16

    if not arguments.train_parquet.is_file():
        print(
            f"FATAL: {arguments.train_parquet} not found.\n"
            "WildGuardMix and ExpGuardMix are GATED. Attach the parquet as a Kaggle Dataset "
            "input, or accept the Hub gate form and set HF_TOKEN in Kaggle Secrets. There is no "
            "anonymous download path -- an unauthenticated fetch returns HTTP 401.",
            file=sys.stderr,
        )
        return 2

    dataset = load_dataset("parquet", data_files=str(arguments.train_parquet), split="train")
    if arguments.max_samples is not None:
        dataset = dataset.select(range(min(arguments.max_samples, len(dataset))))
    print(f"loaded {len(dataset)} rows from {arguments.train_parquet}")

    tokenizer = AutoTokenizer.from_pretrained(arguments.base_repo, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def to_text(batch: dict[str, list[Any]]) -> dict[str, list[str]]:
        """Render a batch of rows into chat-templated training text."""

        rendered: list[str] = []
        keys = list(batch.keys())
        for index in range(len(batch[keys[0]])):
            row = {key: batch[key][index] for key in keys}
            example = build_guard_example(row)
            rendered.append(
                tokenizer.apply_chat_template(
                    [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": example["prompt"]},
                        {"role": "assistant", "content": example["target"]},
                    ],
                    tokenize=False,
                )
            )
        return {"text": rendered}

    textual = dataset.map(to_text, batched=True, remove_columns=dataset.column_names)
    tokenized = textual.map(
        lambda batch: tokenizer(
            batch["text"],
            truncation=True,
            max_length=arguments.sequence_length,
            padding="max_length",
        ),
        batched=True,
        remove_columns=["text"],
    )

    load_kwargs: dict[str, Any] = {"dtype": compute_dtype}
    if arguments.four_bit:
        load_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute_dtype,
        )
        load_kwargs["device_map"] = {"": 0}
    else:
        # 2x T4 is 32 GB aggregate; an fp16 4B base needs sharding to fit with activations.
        load_kwargs["device_map"] = "auto"

    model = AutoModelForCausalLM.from_pretrained(arguments.base_repo, **load_kwargs)
    if arguments.four_bit:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    model = get_peft_model(
        model,
        LoraConfig(
            r=arguments.lora_rank,
            lora_alpha=arguments.lora_alpha,
            lora_dropout=arguments.lora_dropout,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=TARGET_MODULES,
        ),
    )
    model.print_trainable_parameters()
    model.config.use_cache = False

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(arguments.output_dir),
            per_device_train_batch_size=arguments.batch_size,
            gradient_accumulation_steps=arguments.gradient_accumulation_steps,
            num_train_epochs=arguments.epochs,
            learning_rate=arguments.learning_rate,
            warmup_ratio=0.03,
            logging_steps=10,
            save_strategy="epoch",
            seed=arguments.seed,
            data_seed=arguments.seed,
            bf16=device_facts["supports_bf16"],
            fp16=not device_facts["supports_bf16"],
            gradient_checkpointing=True,
            optim="paged_adamw_8bit" if arguments.four_bit else "adamw_torch",
            report_to=[],
        ),
        train_dataset=tokenized,
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
    )
    result = trainer.train()

    model.save_pretrained(arguments.output_dir)
    tokenizer.save_pretrained(arguments.output_dir)

    record = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base_model": arguments.base_repo,
        "base_model_licence": "Apache-2.0",
        "technique": "qlora" if arguments.four_bit else "lora",
        "precision": "bf16" if device_facts["supports_bf16"] else "fp16",
        "device": device_facts,
        "dataset": {
            "path": str(arguments.train_parquet),
            "digest": sha256_file(arguments.train_parquet),
            "rows_used": len(dataset),
            "licence": "see the AIBOM dataset table -- WildGuardMix is ODC-By-1.0 and gated; "
            "ExpGuardMix is CC-BY-4.0 with a narrower research-only click-through",
        },
        "hyperparameters": {
            "lora_r": arguments.lora_rank,
            "lora_alpha": arguments.lora_alpha,
            "lora_dropout": arguments.lora_dropout,
            "sequence_length": arguments.sequence_length,
            "batch_size": arguments.batch_size,
            "gradient_accumulation_steps": arguments.gradient_accumulation_steps,
            "learning_rate": arguments.learning_rate,
            "epochs": arguments.epochs,
            "seed": arguments.seed,
        },
        "train_metrics": dict(result.metrics),
        "reminders": [
            "Recall is the metric. Evaluate with ml/evaluate.py before believing anything.",
            "The adapter is advisory. It may contribute to a Deny and never to an Allow.",
            "Fill the AIBOM (ml/model_card.py) before this artifact goes anywhere.",
        ],
    }
    (arguments.output_dir / "run_record.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    print(f"\nadapter + run_record.json written to {arguments.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
