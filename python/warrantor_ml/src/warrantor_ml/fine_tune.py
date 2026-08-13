"""LoRA / QLoRA fine-tuning for guard models, planned against the Kaggle free tier.

**There is no CPU fallback and there will not be one.** A guard-model fine-tune that silently
drops to CPU does not fail -- it appears to work, runs for a week, and produces an artifact
nobody can tell apart from a real one. So :func:`require_accelerator` raises loudly, by
default, with a message that says what is missing and where to run instead.

Routing this module encodes (measured on the development box: RTX 5080 Laptop, 16,303 MiB
total, 949 MiB consumed by the Windows desktop at idle, 15,055 MiB free, sm_120 Blackwell):

* **DeBERTa-v3-large injection classifier -> local, full fine-tune.** 434M parameters with a
  512-token ceiling fits a complete full-parameter run at batch 16 in roughly 10 GiB. No LoRA,
  no quantisation, no compromise. It is the fastest path to a shippable artifact and should go
  first.
* **Qwen3Guard-Gen-4B -> local QLoRA.** NF4 base plus r=16 adapters at seq 2048 lands around
  8 GiB. LoRA over a bf16 base technically fits but leaves under 2 GiB of margin and will OOM
  the moment the desktop compositor spikes.
* **Qwen3Guard-Gen-8B -> Kaggle.** bf16 weights alone are 15.25 GiB, more than the free VRAM
  before any KV cache. Locally it is a quantised-only model.
* **Full fine-tune of any Qwen3Guard size -> nowhere free.** 4B full FT in bf16 needs roughly
  48-64 GiB. Kaggle's 2xT4 (32 GB aggregate) is not enough.

The Kaggle caveat that changes the numerics: free Kaggle GPUs are 2xT4 (sm_75) or P100
(sm_60). **Neither supports bf16.** Qwen3Guard ships ``torch_dtype: bfloat16``, so a Kaggle run
casts to fp16 and inherits fp16 loss-scaling behaviour -- in a guard model, logit calibration
is exactly what is being measured. :func:`select_precision` picks the dtype from the detected
compute capability and says so out loud.

Zero marginal spend is a standing rule, not a preference. Nothing here calls a paid API,
provisions cloud GPU, or creates an account.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

__all__ = [
    "PROFILES",
    "Accelerator",
    "FineTuneConfig",
    "MissingTrainingDependenciesError",
    "ModelProfile",
    "NoSuitableAcceleratorError",
    "TrainingPlan",
    "VramEstimate",
    "bytes_per_parameter",
    "detect_accelerator",
    "estimate_inference_vram_gib",
    "estimate_training_vram_gib",
    "main",
    "plan",
    "require_accelerator",
    "run",
    "select_precision",
]

GIB = 1024**3
Technique = Literal["qlora", "lora", "full"]
Precision = Literal["bf16", "fp16", "fp32"]

# Bytes per parameter for the frozen base. NF4 is 0.75 rather than the naive 0.5 because
# double-quantisation constants, and the layers kept at higher precision, are not free.
_BYTES_PER_PARAMETER: dict[str, float] = {
    "nf4": 0.75,
    "int8": 1.0,
    "fp16": 2.0,
    "bf16": 2.0,
    "fp32": 4.0,
}

#: Empirical multiplier on ``batch * seq * hidden * 2`` bytes for one transformer layer's
#: retained activations. Calibrated so the estimator reproduces the measured envelopes:
#: 4B QLoRA seq2048 batch2 -> 7-9 GiB, DeBERTa-v3-large full FT batch16 seq512 -> 9-11 GiB.
_ACTIVATION_TENSORS_PER_LAYER = 6

#: Logits are materialised at the output width and then upcast to fp32 for the loss. At a
#: 151,936-token vocabulary this is a first-order term, not a rounding error.
_LOGIT_BYTES_PER_ELEMENT = 6

#: CUDA context, cuBLAS workspaces, fragmentation. Measured floor, not a guess.
_RUNTIME_OVERHEAD_GIB = 1.2

#: Optimizer state per trainable parameter: fp16 weight (2) + fp32 grad (4) + Adam m,v (8).
_TRAINABLE_BYTES_PER_PARAMETER = 14

#: Full fine-tune: bf16 weights (2) + fp32 master (4) + bf16 grads (2) + Adam m,v (8).
_FULL_FT_BYTES_PER_PARAMETER = 16


class NoSuitableAcceleratorError(RuntimeError):
    """Raised when training was requested without a usable GPU. Never downgraded to a warning."""


class MissingTrainingDependenciesError(RuntimeError):
    """Raised when the optional ``train`` extra is not installed."""


# ---------------------------------------------------------------------------
# Model profiles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelProfile:
    """The architectural facts a memory estimate needs. Verified against config.json."""

    key: str
    repo_id: str
    parameters: int
    layers: int
    hidden_size: int
    kv_heads: int
    head_dim: int
    output_width: int
    max_position_embeddings: int
    licence: str
    task: Literal["causal-lm-guard", "sequence-classification"]
    target_modules: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def kv_bytes_per_token(self) -> int:
        """fp16 KV cache cost of one token: 2 (K and V) x layers x kv_heads x head_dim x 2 B."""

        return 2 * self.layers * self.kv_heads * self.head_dim * 2


_QWEN_TARGETS = ("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj")

PROFILES: dict[str, ModelProfile] = {
    "qwen3guard-gen-4b": ModelProfile(
        key="qwen3guard-gen-4b",
        repo_id="Qwen/Qwen3Guard-Gen-4B",
        parameters=4_020_000_000,
        layers=36,
        hidden_size=2560,
        kv_heads=8,
        head_dim=128,
        output_width=151_936,
        max_position_embeddings=32_768,
        licence="Apache-2.0",
        task="causal-lm-guard",
        target_modules=_QWEN_TARGETS,
        notes=(
            "PRIMARY content-moderation base. Highest recall (83.97%) of 14 guard models over "
            "79,331 samples in the ICLR 2026 workshop benchmark, arXiv:2605.28830.",
            "Stock transformers>=4.51.0, Qwen3ForCausalLM, NO trust_remote_code. "
            "tie_word_embeddings=true.",
            "Verified Apache-2.0 with no acceptable-use rider and no NOTICE file -- "
            "redistributable inside a desktop installer.",
        ),
    ),
    "qwen3guard-gen-8b": ModelProfile(
        key="qwen3guard-gen-8b",
        repo_id="Qwen/Qwen3Guard-Gen-8B",
        parameters=8_190_000_000,
        layers=36,
        hidden_size=4096,
        kv_heads=8,
        head_dim=128,
        output_width=151_936,
        max_position_embeddings=32_768,
        licence="Apache-2.0",
        task="causal-lm-guard",
        target_modules=_QWEN_TARGETS,
        notes=(
            "bf16 weights are 15.25 GiB -- more than the free VRAM on a 16 GB laptop card "
            "before any KV cache. Quantised-only locally; bf16 work goes to Kaggle.",
            "tie_word_embeddings=FALSE, unlike the 4B.",
        ),
    ),
    "qwen3guard-gen-0.6b": ModelProfile(
        key="qwen3guard-gen-0.6b",
        repo_id="Qwen/Qwen3Guard-Gen-0.6B",
        parameters=600_000_000,
        layers=28,
        hidden_size=1024,
        kv_heads=8,
        head_dim=128,
        output_width=151_936,
        max_position_embeddings=32_768,
        licence="Apache-2.0",
        task="causal-lm-guard",
        target_modules=_QWEN_TARGETS,
        notes=(
            "Edge / fast pre-filter tier. ONNX builds exist for a CPU-only installer fallback.",
        ),
    ),
    "deberta-v3-large-injection": ModelProfile(
        key="deberta-v3-large-injection",
        repo_id="microsoft/deberta-v3-large",
        parameters=434_000_000,
        layers=24,
        hidden_size=1024,
        kv_heads=16,
        head_dim=64,
        output_width=2,
        max_position_embeddings=512,
        licence="MIT",
        task="sequence-classification",
        target_modules=("query_proj", "key_proj", "value_proj", "dense"),
        notes=(
            "The ONE model in this plan that fully fine-tunes on the local 16 GB card. Fastest "
            "path to a shippable artifact -- run this lane first.",
            "HARD LIMIT: max_position_embeddings = 512. Long prompts, RAG-stuffed context and "
            "multi-turn history MUST be chunked with an overlapping sliding window, because "
            "indirect prompt injection hides in the TAIL of retrieved documents. The windowing "
            "strategy is a design decision, not an implementation detail, and the eval set "
            "needs long-context cases that naive truncation would miss.",
            "Baseline to beat: protectai/deberta-v3-base-prompt-injection-v2. If the fine-tune "
            "does not beat that zero-cost baseline, the training run was not worth the hours.",
        ),
    ),
}


# ---------------------------------------------------------------------------
# Memory arithmetic (pure -- testable with no GPU and no torch)
# ---------------------------------------------------------------------------


def bytes_per_parameter(dtype: str) -> float:
    """Bytes of VRAM one frozen parameter occupies at the given precision."""

    try:
        return _BYTES_PER_PARAMETER[dtype]
    except KeyError as error:
        known = ", ".join(sorted(_BYTES_PER_PARAMETER))
        raise ValueError(f"unknown dtype {dtype!r}; known: {known}") from error


@dataclass(frozen=True)
class VramEstimate:
    """A VRAM estimate broken into its terms, so a surprise can be attributed."""

    total_gib: float
    components_gib: dict[str, float]
    note: str = (
        "Planning estimate, roughly +/-20%. Calibrated against measured envelopes; it is not a "
        "substitute for watching nvidia-smi on the first run."
    )

    def fits_within(self, available_gib: float) -> bool:
        """Whether the estimate fits, leaving no headroom margin of its own."""

        return self.total_gib <= available_gib


def estimate_inference_vram_gib(
    profile: ModelProfile,
    weight_dtype: str = "bf16",
    context_tokens: int = 8192,
) -> VramEstimate:
    """Estimate inference VRAM: weights + KV cache + runtime overhead."""

    weights = profile.parameters * bytes_per_parameter(weight_dtype) / GIB
    kv_cache = context_tokens * profile.kv_bytes_per_token / GIB
    components = {
        "weights": round(weights, 3),
        "kv_cache": round(kv_cache, 3),
        "runtime_overhead": _RUNTIME_OVERHEAD_GIB,
    }
    return VramEstimate(round(sum(components.values()), 3), components)


def estimate_training_vram_gib(
    profile: ModelProfile,
    technique: Technique = "qlora",
    base_dtype: str = "nf4",
    lora_rank: int = 16,
    sequence_length: int = 2048,
    batch_size: int = 2,
    gradient_checkpointing: bool = True,
) -> VramEstimate:
    """Estimate peak training VRAM, broken into attributable terms.

    Terms: frozen base weights, trainable parameters and their optimizer state, retained
    activations, materialised logits, and CUDA runtime overhead. The logit term is included
    explicitly because at a 151,936-token vocabulary it is a first-order cost that a
    weights-only mental model misses entirely.
    """

    activation_unit = batch_size * sequence_length * profile.hidden_size * 2

    if technique == "full":
        base = profile.parameters * _FULL_FT_BYTES_PER_PARAMETER / GIB
        trainable_state = 0.0
    else:
        base = profile.parameters * bytes_per_parameter(base_dtype) / GIB
        modules_per_layer = len(profile.target_modules)
        trainable_parameters = (
            2 * lora_rank * profile.hidden_size * modules_per_layer * profile.layers
        )
        trainable_state = trainable_parameters * _TRAINABLE_BYTES_PER_PARAMETER / GIB

    if gradient_checkpointing:
        activations = (
            profile.layers * activation_unit + _ACTIVATION_TENSORS_PER_LAYER * activation_unit
        ) / GIB
    else:
        activations = profile.layers * _ACTIVATION_TENSORS_PER_LAYER * activation_unit / GIB

    logits = (
        batch_size * sequence_length * profile.output_width * _LOGIT_BYTES_PER_ELEMENT / GIB
        if profile.task == "causal-lm-guard"
        else batch_size * profile.output_width * _LOGIT_BYTES_PER_ELEMENT / GIB
    )

    components = {
        "base_weights": round(base, 3),
        "trainable_and_optimizer": round(trainable_state, 3),
        "activations": round(activations, 3),
        "logits": round(logits, 3),
        "runtime_overhead": _RUNTIME_OVERHEAD_GIB,
    }
    return VramEstimate(round(sum(components.values()), 3), components)


def select_precision(compute_capability: tuple[int, int]) -> tuple[Precision, str]:
    """Choose a training precision from the GPU's compute capability, and say why.

    Ampere and later (sm_80+) get bf16. Turing (T4, sm_75) and Pascal (P100, sm_60) -- both of
    the free Kaggle options -- have no bf16 path and no FlashAttention-2, so they get fp16 plus
    a warning that matters: a guard model's whole product is a calibrated logit, and fp16 loss
    scaling is exactly where calibration goes quietly wrong.
    """

    major, _minor = compute_capability
    if major >= 8:
        return "bf16", f"sm_{major}x supports bf16 natively; matching the base model's dtype."
    return (
        "fp16",
        f"sm_{major}x has NO bf16 support (this is the Kaggle T4/P100 case). Qwen3Guard ships "
        "torch_dtype=bfloat16, so weights are cast to fp16 and training inherits fp16 "
        "loss-scaling behaviour. VERIFY loss-scale stability on a short run before committing "
        "30 weekly hours: logit calibration is the property being measured.",
    )


# ---------------------------------------------------------------------------
# Accelerator detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Accelerator:
    """A detected CUDA device."""

    name: str
    total_memory_gib: float
    free_memory_gib: float
    compute_capability: tuple[int, int]
    device_count: int
    torch_version: str

    @property
    def supports_bf16(self) -> bool:
        """Whether the device has native bf16 (Ampere and later)."""

        return self.compute_capability[0] >= 8


_NO_GPU_MESSAGE = """\
No CUDA device is available, and this script has NO CPU fallback by design.

A guard-model fine-tune that silently falls back to CPU does not fail -- it appears to work,
takes days, and yields an artifact indistinguishable from a real one until it is in front of a
deny gate. Failing loudly here is the cheap outcome.

Where to run instead (all free, zero marginal spend):
  * Kaggle    -- 30 GPU-hours/week, 2x T4 (sm_75) or P100 (sm_60), fp16 only, no bf16 and no
                 FlashAttention-2. This is the training tier. See ml/kaggle/README.md.
  * Local     -- an RTX-class card with >= 10 GiB free runs the 4B QLoRA lane and the full
                 DeBERTa-v3-large fine-tune.

To see the plan without a GPU, re-run with --dry-run.
"""


def detect_accelerator() -> Accelerator:
    """Detect the CUDA device, raising loudly rather than degrading.

    Raises:
        MissingTrainingDependenciesError: torch is not installed.
        NoSuitableAcceleratorError: torch is installed but no CUDA device is usable.
    """

    try:
        import torch
    except ImportError as error:
        raise MissingTrainingDependenciesError(
            "torch is not installed. Install the optional training extra:\n"
            "    pip install -e 'python/warrantor_ml[train]'\n"
            "On Blackwell (sm_120) you need a cu128 or newer wheel; stock cu121/cu124 builds do "
            "not generate code for sm_120. Verify the exact wheel matrix (torch cu128 + "
            "bitsandbytes sm_120 + peft) in a throwaway venv BEFORE writing training code "
            "against it -- if bitsandbytes has no sm_120 kernels, the local QLoRA lane "
            "collapses to DeBERTa-only."
        ) from error

    if not torch.cuda.is_available():
        raise NoSuitableAcceleratorError(_NO_GPU_MESSAGE)

    index = torch.cuda.current_device()
    properties = torch.cuda.get_device_properties(index)
    free_bytes, total_bytes = torch.cuda.mem_get_info(index)
    return Accelerator(
        name=properties.name,
        total_memory_gib=round(total_bytes / GIB, 2),
        free_memory_gib=round(free_bytes / GIB, 2),
        compute_capability=(properties.major, properties.minor),
        device_count=torch.cuda.device_count(),
        torch_version=torch.__version__,
    )


def require_accelerator(minimum_free_gib: float) -> Accelerator:
    """Detect a GPU and refuse to continue if it cannot hold the run."""

    accelerator = detect_accelerator()
    if accelerator.free_memory_gib < minimum_free_gib:
        raise NoSuitableAcceleratorError(
            f"{accelerator.name} has {accelerator.free_memory_gib:.2f} GiB free but this run "
            f"needs an estimated {minimum_free_gib:.2f} GiB.\n"
            "Refusing to start rather than OOM three hours in. Options: lower --batch-size, "
            "lower --sequence-length, switch --technique to qlora, or move the run to Kaggle."
        )
    return accelerator


# ---------------------------------------------------------------------------
# Configuration and plan
# ---------------------------------------------------------------------------


@dataclass
class FineTuneConfig:
    """Everything that defines a run. Serialised verbatim into the training plan."""

    profile_key: str = "qwen3guard-gen-4b"
    technique: Technique = "qlora"
    base_dtype: str = "nf4"
    dataset_id: str = "wildguardmix"
    dataset_split: str = "train"
    lora_rank: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    sequence_length: int = 2048
    batch_size: int = 2
    gradient_accumulation_steps: int = 8
    learning_rate: float = 1e-4
    epochs: float = 1.0
    warmup_ratio: float = 0.03
    weight_decay: float = 0.0
    seed: int = 20260812
    gradient_checkpointing: bool = True
    output_dir: Path = Path("artifacts/guard-lora")
    max_samples: int | None = None
    headroom_gib: float = 1.0

    def profile(self) -> ModelProfile:
        """The model profile this config targets."""

        try:
            return PROFILES[self.profile_key]
        except KeyError as error:
            known = ", ".join(sorted(PROFILES))
            raise ValueError(f"unknown profile {self.profile_key!r}; known: {known}") from error


@dataclass(frozen=True)
class TrainingPlan:
    """A fully resolved run description. Produced without touching a GPU."""

    config: FineTuneConfig
    profile: ModelProfile
    estimate: VramEstimate
    minimum_free_gib: float
    effective_batch_size: int
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialise the plan for the run record."""

        config = asdict(self.config)
        config["output_dir"] = str(self.config.output_dir)
        return {
            "config": config,
            "profile": {
                "key": self.profile.key,
                "repo_id": self.profile.repo_id,
                "parameters": self.profile.parameters,
                "licence": self.profile.licence,
                "task": self.profile.task,
                "max_position_embeddings": self.profile.max_position_embeddings,
                "notes": list(self.profile.notes),
            },
            "vram_estimate_gib": {
                "total": self.estimate.total_gib,
                "components": self.estimate.components_gib,
                "note": self.estimate.note,
            },
            "minimum_free_gib": self.minimum_free_gib,
            "effective_batch_size": self.effective_batch_size,
            "warnings": list(self.warnings),
        }


def plan(config: FineTuneConfig) -> TrainingPlan:
    """Resolve a config into a plan. Pure: no GPU, no torch, no network."""

    profile = config.profile()
    warnings: list[str] = []

    if config.sequence_length > profile.max_position_embeddings:
        warnings.append(
            f"sequence_length {config.sequence_length} exceeds {profile.repo_id}'s "
            f"max_position_embeddings of {profile.max_position_embeddings}. For "
            "deberta-v3-large this is an ARCHITECTURAL ceiling, not a tunable -- chunk with an "
            "overlapping sliding window or the tail of the payload is never inspected, which is "
            "precisely where indirect injection hides."
        )
    if config.technique == "full" and profile.parameters > 1_000_000_000:
        warnings.append(
            f"full fine-tune of {profile.parameters / 1e9:.1f}B parameters needs roughly "
            f"{profile.parameters * _FULL_FT_BYTES_PER_PARAMETER / GIB:.0f} GiB of optimizer "
            "state alone. Not available on any free tier -- Kaggle's 2xT4 is 32 GB aggregate. "
            "Use qlora."
        )
    if config.technique == "lora" and config.base_dtype in {"bf16", "fp16"}:
        warnings.append(
            "LoRA over an unquantised base leaves very little margin on a 16 GB card and will "
            "OOM when the desktop compositor spikes. Prefer technique=qlora locally."
        )
    if config.dataset_id in {"wildguardmix", "expguardmix"}:
        warnings.append(
            f"{config.dataset_id} is GATED on Hugging Face. Accept the form and export a read "
            "token before this run, or the data step fails with HTTP 401. Run "
            "`warrantor-ml-datasets --preflight` first."
        )
    if config.dataset_id == "expguardmix":
        warnings.append(
            "ExpGuardMix's gate form requires affirming research-only use, which is NARROWER "
            "than its CC-BY-4.0 licence. Do not train a commercially shipped pack on it without "
            "a written read from counsel."
        )

    estimate = estimate_training_vram_gib(
        profile,
        technique=config.technique,
        base_dtype=config.base_dtype,
        lora_rank=config.lora_rank,
        sequence_length=config.sequence_length,
        batch_size=config.batch_size,
        gradient_checkpointing=config.gradient_checkpointing,
    )
    return TrainingPlan(
        config=config,
        profile=profile,
        estimate=estimate,
        minimum_free_gib=round(estimate.total_gib + config.headroom_gib, 3),
        effective_batch_size=config.batch_size * config.gradient_accumulation_steps,
        warnings=tuple(warnings),
    )


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _import_training_stack() -> dict[str, Any]:  # pragma: no cover - needs the train extra
    """Import the heavy training stack, or raise a message that says how to install it."""

    try:
        import torch
        from datasets import load_dataset
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from transformers import (
            AutoModelForCausalLM,
            AutoModelForSequenceClassification,
            AutoTokenizer,
            BitsAndBytesConfig,
            Trainer,
            TrainingArguments,
        )
    except ImportError as error:
        raise MissingTrainingDependenciesError(
            f"the training stack is not installed ({error}). Install the optional extra:\n"
            "    pip install -e 'python/warrantor_ml[train,hub]'"
        ) from error
    return {
        "torch": torch,
        "load_dataset": load_dataset,
        "LoraConfig": LoraConfig,
        "get_peft_model": get_peft_model,
        "prepare_model_for_kbit_training": prepare_model_for_kbit_training,
        "AutoModelForCausalLM": AutoModelForCausalLM,
        "AutoModelForSequenceClassification": AutoModelForSequenceClassification,
        "AutoTokenizer": AutoTokenizer,
        "BitsAndBytesConfig": BitsAndBytesConfig,
        "Trainer": Trainer,
        "TrainingArguments": TrainingArguments,
    }


def run(
    config: FineTuneConfig, training_plan: TrainingPlan | None = None
) -> Path:  # pragma: no cover
    """Execute the fine-tune. Requires a GPU; raises rather than falling back to CPU.

    Returns:
        The output directory containing the adapter, the tokenizer and ``run_record.json``.
    """

    resolved = training_plan or plan(config)
    accelerator = require_accelerator(resolved.minimum_free_gib)
    precision, precision_reason = select_precision(accelerator.compute_capability)
    stack = _import_training_stack()
    torch = stack["torch"]

    torch.manual_seed(config.seed)
    profile = resolved.profile
    compute_dtype = torch.bfloat16 if precision == "bf16" else torch.float16

    quantization_config = None
    if config.technique == "qlora":
        quantization_config = stack["BitsAndBytesConfig"](
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=compute_dtype,
        )

    tokenizer = stack["AutoTokenizer"].from_pretrained(profile.repo_id, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    loader = (
        stack["AutoModelForSequenceClassification"]
        if profile.task == "sequence-classification"
        else stack["AutoModelForCausalLM"]
    )
    load_kwargs: dict[str, Any] = {
        "dtype": compute_dtype,
        "device_map": {"": accelerator_index(torch)},
    }
    if quantization_config is not None:
        load_kwargs["quantization_config"] = quantization_config
    if profile.task == "sequence-classification":
        load_kwargs["num_labels"] = profile.output_width
    model = loader.from_pretrained(profile.repo_id, **load_kwargs)

    if config.technique == "qlora":
        model = stack["prepare_model_for_kbit_training"](
            model, use_gradient_checkpointing=config.gradient_checkpointing
        )
    if config.technique in {"qlora", "lora"}:
        model = stack["get_peft_model"](
            model,
            stack["LoraConfig"](
                r=config.lora_rank,
                lora_alpha=config.lora_alpha,
                lora_dropout=config.lora_dropout,
                bias="none",
                task_type="SEQ_CLS" if profile.task == "sequence-classification" else "CAUSAL_LM",
                target_modules=list(profile.target_modules),
            ),
        )
    if config.gradient_checkpointing:
        model.gradient_checkpointing_enable()

    dataset = _load_training_dataset(stack, config)
    tokenized = dataset.map(
        lambda batch: tokenizer(
            batch["text"],
            truncation=True,
            max_length=config.sequence_length,
            padding="max_length",
        ),
        batched=True,
        remove_columns=[name for name in dataset.column_names if name != "labels"],
    )

    config.output_dir.mkdir(parents=True, exist_ok=True)
    trainer = stack["Trainer"](
        model=model,
        args=stack["TrainingArguments"](
            output_dir=str(config.output_dir),
            per_device_train_batch_size=config.batch_size,
            gradient_accumulation_steps=config.gradient_accumulation_steps,
            num_train_epochs=config.epochs,
            learning_rate=config.learning_rate,
            warmup_ratio=config.warmup_ratio,
            weight_decay=config.weight_decay,
            logging_steps=10,
            save_strategy="epoch",
            seed=config.seed,
            data_seed=config.seed,
            bf16=precision == "bf16",
            fp16=precision == "fp16",
            gradient_checkpointing=config.gradient_checkpointing,
            optim="paged_adamw_8bit" if config.technique == "qlora" else "adamw_torch",
            report_to=[],
        ),
        train_dataset=tokenized,
    )
    trainer.train()
    model.save_pretrained(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)

    record = {
        "plan": resolved.to_dict(),
        "accelerator": asdict(accelerator),
        "precision": precision,
        "precision_reason": precision_reason,
    }
    (config.output_dir / "run_record.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    return config.output_dir


def accelerator_index(torch_module: Any) -> int:  # pragma: no cover - needs torch
    """The CUDA device index the run pins itself to."""

    return int(torch_module.cuda.current_device())


def _load_training_dataset(
    stack: dict[str, Any], config: FineTuneConfig
) -> Any:  # pragma: no cover
    """Load and normalise the training corpus to ``text`` + ``labels`` columns."""

    from .datasets import ensure_available, get_dataset

    spec = get_dataset(config.dataset_id)
    paths = ensure_available(spec, splits=(config.dataset_split,))
    dataset = stack["load_dataset"](
        "parquet", data_files=str(paths[config.dataset_split]), split="train"
    )
    if config.max_samples is not None:
        dataset = dataset.select(range(min(config.max_samples, len(dataset))))
    return dataset


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-fine-tune``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-fine-tune",
        description="LoRA/QLoRA fine-tune a guard model. Fails loudly without a GPU.",
    )
    parser.add_argument("--profile", default="qwen3guard-gen-4b", choices=sorted(PROFILES))
    parser.add_argument("--technique", default="qlora", choices=("qlora", "lora", "full"))
    parser.add_argument("--base-dtype", default="nf4", choices=sorted(_BYTES_PER_PARAMETER))
    parser.add_argument("--dataset", default="wildguardmix")
    parser.add_argument("--split", default="train")
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--sequence-length", type=int, default=2048)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--grad-accum", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=1e-4)
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=20260812)
    parser.add_argument("--max-samples", type=int)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/guard-lora"))
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan and the VRAM estimate, then exit WITHOUT training",
    )
    parser.add_argument("--json", action="store_true", help="emit the plan as JSON")
    return parser


def _config_from_arguments(arguments: argparse.Namespace) -> FineTuneConfig:
    """Build a config from parsed CLI arguments."""

    return FineTuneConfig(
        profile_key=arguments.profile,
        technique=arguments.technique,
        base_dtype=arguments.base_dtype,
        dataset_id=arguments.dataset,
        dataset_split=arguments.split,
        lora_rank=arguments.lora_rank,
        lora_alpha=arguments.lora_alpha,
        sequence_length=arguments.sequence_length,
        batch_size=arguments.batch_size,
        gradient_accumulation_steps=arguments.grad_accum,
        learning_rate=arguments.learning_rate,
        epochs=arguments.epochs,
        seed=arguments.seed,
        max_samples=arguments.max_samples,
        output_dir=arguments.output_dir,
    )


def _print_plan(training_plan: TrainingPlan) -> None:
    """Human-readable plan."""

    print("=" * 72)
    print(f"model      {training_plan.profile.repo_id}  ({training_plan.profile.licence})")
    print(
        f"technique  {training_plan.config.technique}  base_dtype={training_plan.config.base_dtype}"
    )
    print(
        f"batch      {training_plan.config.batch_size} x "
        f"{training_plan.config.gradient_accumulation_steps} accum = "
        f"{training_plan.effective_batch_size} effective"
    )
    print(f"seq len    {training_plan.config.sequence_length}")
    print("-" * 72)
    print(f"VRAM estimate  {training_plan.estimate.total_gib:.2f} GiB")
    for name, value in training_plan.estimate.components_gib.items():
        print(f"    {name:26} {value:>7.2f} GiB")
    print(f"    {'required free (with headroom)':26} {training_plan.minimum_free_gib:>7.2f} GiB")
    print(f"    {training_plan.estimate.note}")
    for warning in training_plan.warnings:
        print("-" * 72)
        print(f"WARNING: {warning}")
    print("=" * 72)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-fine-tune``."""

    arguments = build_parser().parse_args(argv)
    training_plan = plan(_config_from_arguments(arguments))

    if arguments.json:
        print(json.dumps(training_plan.to_dict(), indent=2))
    else:
        _print_plan(training_plan)

    if arguments.dry_run:
        print("PLAN ONLY -- no GPU was touched and no training was performed.")
        return 0

    try:
        run(training_plan.config, training_plan)
    except (NoSuitableAcceleratorError, MissingTrainingDependenciesError) as error:
        print(f"\nTRAINING ABORTED\n{error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
