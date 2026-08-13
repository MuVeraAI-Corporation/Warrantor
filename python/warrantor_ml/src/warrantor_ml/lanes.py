"""The three compute lanes, and refusing a run before it starts rather than at hour eleven.

:mod:`warrantor_ml.fine_tune` already refuses a configuration whose VRAM estimate exceeds free
memory, and its estimator is pure arithmetic pinned to measured envelopes. That is half of a
refusal. The other half is **wall clock and precision**, and both are lane properties:

* **Kaggle sessions are killed at 12 hours.** A 30-hour weekly budget spent discovering that at
  hour eleven is a week gone. The cap is a planning input, so :func:`resolve` refuses a recipe
  whose estimated wall clock exceeds it and points at the ``save_steps`` / ``--resume-from``
  contract that turns one 30-hour run into three resumable ones.
* **Kaggle's T4 (sm_75) and P100 (sm_60) have no bf16.** Qwen3Guard ships
  ``torch_dtype: bfloat16``, so a Kaggle run casts to fp16 and inherits fp16 loss scaling. A
  guard model's product is a calibrated logit. That makes a Kaggle-trained candidate and a
  locally-measured baseline a **confounded comparison**, which is why the lane and the precision
  are recorded on every run record and why :mod:`warrantor_ml.parity` refuses to compare across
  them rather than reporting a delta.

Nothing here dispatches anything. :func:`resolve` is pure arithmetic over declared facts and
answers the routing question before a single byte is downloaded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .fine_tune import (
    FineTuneConfig,
    Precision,
    estimate_training_vram_gib,
    plan,
    select_precision,
)

__all__ = [
    "LANES",
    "Lane",
    "LaneResolution",
    "LaneUnsuitableError",
    "get_lane",
    "resolve",
]

LaneKey = Literal["local-rtx5080", "kaggle-t4x2", "kaggle-p100", "modal-a100"]


class LaneUnsuitableError(RuntimeError):
    """Raised when a recipe cannot run on a lane. Never downgraded to a warning.

    Same posture as ``fine_tune.require_accelerator``: refusing to start is the cheap outcome
    and OOM-ing three hours in is the expensive one. The message always names an alternative,
    because "no" without a next step gets worked around rather than fixed.
    """


@dataclass(frozen=True)
class Lane:
    """One place a training run can happen, and what it costs to be there.

    ``throughput_tokens_per_second`` is a coarse planning constant per lane, in the same spirit
    as the VRAM estimator's calibrated multipliers: good enough to tell a 4-hour run from a
    40-hour one, never a substitute for the first real step-time reading. It is deliberately
    conservative -- an optimistic constant produces a plan that fits on paper and dies at the
    session cap.
    """

    key: str
    description: str
    usable_vram_gib: float
    supports_bf16: bool
    compute_capability: tuple[int, int]
    #: Hard session limit in hours. ``None`` means the lane does not kill long runs.
    session_cap_hours: float | None
    #: Weekly budget in GPU-hours. ``None`` means uncapped or credit-funded.
    weekly_budget_hours: float | None
    throughput_tokens_per_second: float
    device_count: int
    notes: tuple[str, ...] = ()

    @property
    def precision(self) -> tuple[Precision, str]:
        """The precision this lane forces, and why, via ``fine_tune.select_precision``."""

        return select_precision(self.compute_capability)


LANES: dict[str, Lane] = {
    "local-rtx5080": Lane(
        key="local-rtx5080",
        description="RTX 5080 Laptop, 16 GB, sm_120 Blackwell. The development box.",
        # 16,303 MiB total minus ~949 MiB the Windows desktop holds at idle.
        usable_vram_gib=14.7,
        supports_bf16=True,
        compute_capability=(12, 0),
        session_cap_hours=None,
        weekly_budget_hours=None,
        throughput_tokens_per_second=1400.0,
        device_count=1,
        notes=(
            "bf16 native, so this is the only lane whose numerics match the base model's "
            "declared dtype. Baselines were measured here; a candidate measured here is "
            "comparable to them.",
            "sm_120 wheel matrix (torch cu128 + bitsandbytes sm_120 + peft) is UNVERIFIED. If "
            "bitsandbytes has no sm_120 kernels the local QLoRA lane collapses to DeBERTa-only.",
        ),
    ),
    "kaggle-t4x2": Lane(
        key="kaggle-t4x2",
        description="Kaggle free tier, 2x Tesla T4 (sm_75), 15 GB each.",
        usable_vram_gib=14.0,
        supports_bf16=False,
        compute_capability=(7, 5),
        session_cap_hours=12.0,
        weekly_budget_hours=30.0,
        throughput_tokens_per_second=520.0,
        device_count=2,
        notes=(
            "NO bf16 and NO FlashAttention-2. Runs cast to fp16 and inherit fp16 loss scaling.",
            "32 GB aggregate across two cards does NOT make a 32 GB card: without model "
            "parallelism a run must fit in one 15 GB device.",
        ),
    ),
    "kaggle-p100": Lane(
        key="kaggle-p100",
        description="Kaggle free tier, 1x Tesla P100 (sm_60), 16 GB.",
        usable_vram_gib=15.0,
        supports_bf16=False,
        compute_capability=(6, 0),
        session_cap_hours=12.0,
        weekly_budget_hours=30.0,
        throughput_tokens_per_second=420.0,
        device_count=1,
        notes=(
            "Older than the T4 and slower for this workload, but a single 16 GB device rather "
            "than two 15 GB ones, so it fits some configurations the T4 lane cannot.",
        ),
    ),
    "modal-a100": Lane(
        key="modal-a100",
        description="Modal serverless A100 80 GB (sm_80), per-second billing against a grant.",
        usable_vram_gib=78.0,
        supports_bf16=True,
        compute_capability=(8, 0),
        session_cap_hours=None,
        weekly_budget_hours=None,
        throughput_tokens_per_second=3600.0,
        device_count=1,
        notes=(
            "bf16 native, so numerically comparable to the local lane even though the hardware "
            "differs. The only lane that can hold a configuration the 16 GB cards cannot.",
            "Credit-funded, not free. Every run here spends a finite grant, so it is the last "
            "lane to try and never the default.",
        ),
    ),
}


def get_lane(key: str) -> Lane:
    """Look up a lane, or fail naming the lanes that exist."""

    try:
        return LANES[key]
    except KeyError as error:
        known = ", ".join(sorted(LANES))
        raise LaneUnsuitableError(f"unknown lane {key!r}; declared: {known}") from error


@dataclass(frozen=True)
class LaneResolution:
    """A recipe resolved against a lane: precision, memory, wall clock, and the resume contract."""

    lane: Lane
    precision: Precision
    precision_reason: str
    estimated_vram_gib: float
    estimated_hours: float
    fits: bool
    #: Checkpoint interval in optimizer steps, or ``None`` on a lane with no session cap.
    save_steps: int | None
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialise into the run record, so the gate can read lane and precision back."""

        return {
            "lane": self.lane.key,
            "precision": self.precision,
            "precision_reason": self.precision_reason,
            "estimated_vram_gib": self.estimated_vram_gib,
            "usable_vram_gib": self.lane.usable_vram_gib,
            "estimated_hours": self.estimated_hours,
            "session_cap_hours": self.lane.session_cap_hours,
            "fits": self.fits,
            "save_steps": self.save_steps,
            "warnings": list(self.warnings),
        }


def _estimated_hours(config: FineTuneConfig, lane: Lane, corpus_rows: int) -> float:
    """Coarse wall-clock estimate: tokens to process divided by a per-lane throughput.

    Deliberately ignores dataloading, checkpoint writes and the first-step compile. Those make
    the true figure larger, never smaller, which is the direction a refusal wants to err in.
    """

    tokens = corpus_rows * config.sequence_length * max(config.epochs, 0.0)
    return tokens / max(lane.throughput_tokens_per_second, 1.0) / 3600.0


def resolve(
    config: FineTuneConfig,
    lane_key: str,
    corpus_rows: int,
    resume_from: str | None = None,
) -> LaneResolution:
    """Resolve a recipe onto a lane, refusing a configuration that cannot complete there.

    Two refusals, both before anything is downloaded:

    1. **It does not fit.** The estimate plus the config's headroom exceeds the lane's usable
       VRAM. Reuses ``fine_tune.estimate_training_vram_gib`` -- the same pure arithmetic the
       ``--dry-run`` path prints, so a lane decision and a local dry run never disagree.
    2. **It cannot finish.** The estimated wall clock exceeds the lane's session cap and no
       ``resume_from`` was supplied. With a resume checkpoint the run is allowed: three 10-hour
       segments against a 12-hour cap is a plan, one 30-hour run is not.

    Raises:
        LaneUnsuitableError: naming the alternative lane or the parameter to change.
    """

    lane = get_lane(lane_key)
    profile = config.profile()
    precision, precision_reason = lane.precision
    estimate = estimate_training_vram_gib(
        profile,
        technique=config.technique,
        base_dtype=config.base_dtype,
        lora_rank=config.lora_rank,
        sequence_length=config.sequence_length,
        batch_size=config.batch_size,
        gradient_checkpointing=config.gradient_checkpointing,
    )
    required = estimate.total_gib + config.headroom_gib
    warnings = list(plan(config).warnings)

    if required > lane.usable_vram_gib:
        roomier = sorted(
            (item for item in LANES.values() if item.usable_vram_gib >= required),
            key=lambda item: item.usable_vram_gib,
        )
        suggestion = (
            f"Lanes that hold it: {', '.join(item.key for item in roomier)}."
            if roomier
            else "No declared lane holds it -- lower --sequence-length or --batch-size, or "
            "switch --technique to qlora."
        )
        raise LaneUnsuitableError(
            f"{config.profile_key} {config.technique} needs an estimated {required:.2f} GiB but "
            f"{lane.key} has {lane.usable_vram_gib:.2f} GiB usable. Refusing to start rather "
            f"than OOM part-way through. {suggestion}"
        )

    hours = _estimated_hours(config, lane, corpus_rows)
    save_steps: int | None = None
    if lane.session_cap_hours is not None:
        steps_per_epoch = max(
            1, corpus_rows // max(config.batch_size * config.gradient_accumulation_steps, 1)
        )
        total_steps = max(1, int(steps_per_epoch * max(config.epochs, 1.0)))
        # Aim for a checkpoint roughly every tenth of a session cap, so at most ~1.2 hours of
        # compute is lost to a kill. Bounded below so a short run does not checkpoint every step.
        segments = max(1, int(hours / (lane.session_cap_hours / 10)) or 1)
        save_steps = max(20, total_steps // max(segments, 1))

        if hours > lane.session_cap_hours and resume_from is None:
            raise LaneUnsuitableError(
                f"estimated {hours:.1f} h exceeds {lane.key}'s {lane.session_cap_hours:.0f} h "
                "session cap and no --resume-from was given. The session WILL be killed and the "
                f"run lost. Either pass --resume-from with save_steps={save_steps} and run it in "
                f"segments, cut the corpus with --max-samples, or move to "
                f"{'modal-a100' if lane.key.startswith('kaggle') else 'kaggle-t4x2'}."
            )
        if lane.weekly_budget_hours is not None and hours > lane.weekly_budget_hours:
            warnings.append(
                f"estimated {hours:.1f} h exceeds the whole {lane.weekly_budget_hours:.0f} "
                "GPU-h weekly budget for this lane; there is no second attempt this week"
            )

    if not lane.supports_bf16:
        warnings.append(
            f"{lane.key} trains in {precision}. A candidate trained here is NOT numerically "
            "comparable to a baseline measured on a bf16 lane, and the parity gate will refuse "
            "the comparison rather than report a delta. Re-run the eval on the candidate's own "
            "lane before claiming an improvement."
        )

    return LaneResolution(
        lane=lane,
        precision=precision,
        precision_reason=precision_reason,
        estimated_vram_gib=estimate.total_gib,
        estimated_hours=round(hours, 2),
        fits=True,
        save_steps=save_steps,
        warnings=tuple(warnings),
    )
