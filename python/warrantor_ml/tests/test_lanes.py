"""Lanes: refusing before the run, on memory and on wall clock, and recording the precision."""

from __future__ import annotations

import pytest

from warrantor_ml.fine_tune import FineTuneConfig
from warrantor_ml.lanes import LANES, LaneUnsuitableError, get_lane, resolve


def test_all_three_lane_families_are_declared() -> None:
    assert set(LANES) == {"local-rtx5080", "kaggle-t4x2", "kaggle-p100", "modal-a100"}


def test_an_unknown_lane_names_the_declared_ones() -> None:
    with pytest.raises(LaneUnsuitableError, match="declared:"):
        get_lane("colab-free")


def test_only_the_kaggle_lanes_lack_bf16() -> None:
    """T4 (sm_75) and P100 (sm_60) have no bf16 path. Qwen3Guard ships bfloat16."""

    assert get_lane("kaggle-t4x2").supports_bf16 is False
    assert get_lane("kaggle-p100").supports_bf16 is False
    assert get_lane("local-rtx5080").supports_bf16 is True
    assert get_lane("modal-a100").supports_bf16 is True


def test_the_kaggle_lanes_resolve_to_fp16_with_the_calibration_warning() -> None:
    precision, reason = get_lane("kaggle-t4x2").precision
    assert precision == "fp16"
    assert "calibration" in reason or "loss-scaling" in reason


def test_only_the_kaggle_lanes_carry_a_session_cap() -> None:
    assert get_lane("kaggle-t4x2").session_cap_hours == 12.0
    assert get_lane("kaggle-p100").session_cap_hours == 12.0
    assert get_lane("local-rtx5080").session_cap_hours is None


def _small_config(**overrides: object) -> FineTuneConfig:
    config = FineTuneConfig(
        profile_key="qwen3guard-gen-0.6b",
        technique="lora",
        base_dtype="bf16",
        sequence_length=512,
        batch_size=1,
        epochs=1.0,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


# ── refusal 1: it does not fit ──────────────────────────────────────────────────────────


def test_a_configuration_that_does_not_fit_is_refused_before_it_starts() -> None:
    """Refusing to start is the cheap outcome; OOM-ing three hours in is the expensive one."""

    oversized = FineTuneConfig(
        profile_key="qwen3guard-gen-8b",
        technique="full",
        base_dtype="bf16",
        sequence_length=4096,
        batch_size=8,
    )
    with pytest.raises(LaneUnsuitableError, match="Refusing to start rather than OOM"):
        resolve(oversized, "kaggle-t4x2", corpus_rows=1000)


def test_the_refusal_names_a_roomier_lane_when_one_exists() -> None:
    big = FineTuneConfig(
        profile_key="qwen3guard-gen-8b",
        technique="qlora",
        base_dtype="nf4",
        sequence_length=8192,
        batch_size=4,
    )
    with pytest.raises(LaneUnsuitableError, match="modal-a100"):
        resolve(big, "kaggle-t4x2", corpus_rows=1000)


def test_a_small_run_fits_the_local_lane() -> None:
    resolution = resolve(_small_config(), "local-rtx5080", corpus_rows=500)
    assert resolution.fits is True
    assert resolution.precision == "bf16"


# ── refusal 2: it cannot finish ─────────────────────────────────────────────────────────


def test_a_run_that_cannot_finish_inside_the_session_cap_is_refused() -> None:
    """Discovering the 12-hour cap at hour eleven costs the week's 30 GPU-hour budget."""

    with pytest.raises(LaneUnsuitableError, match="session cap"):
        resolve(_small_config(), "kaggle-t4x2", corpus_rows=2_000_000)


def test_the_refusal_quotes_a_save_steps_value_to_resume_from() -> None:
    with pytest.raises(LaneUnsuitableError, match="save_steps="):
        resolve(_small_config(), "kaggle-t4x2", corpus_rows=2_000_000)


def test_a_resume_checkpoint_permits_a_run_over_the_cap() -> None:
    """Three 10-hour segments against a 12-hour cap is a plan; one 30-hour run is not."""

    resolution = resolve(
        _small_config(), "kaggle-t4x2", corpus_rows=2_000_000, resume_from="checkpoint-400"
    )
    assert resolution.fits is True
    assert resolution.save_steps is not None


def test_a_lane_that_cannot_be_interrupted_needs_no_save_steps() -> None:
    """The local lane has no cap AND cannot be preempted, so checkpointing buys nothing.

    Named for the real rule. This test used to be called `no_session_cap_means_no_save_steps`,
    which stated the WRONG contract -- it passed only because the lane it happens to use is also
    not preemptible. See the test below for the case that name let through.
    """
    resolution = resolve(_small_config(), "local-rtx5080", corpus_rows=500)
    assert LANES["local-rtx5080"].preemptible is False
    assert resolution.save_steps is None


def test_a_preemptible_lane_checkpoints_even_without_a_session_cap() -> None:
    """The regression that cost a run on 2026-09-01.

    Modal declares no session cap, so the old rule gave it `save_steps = None`. It then preempted
    a T1 arm at step 323 of 705 and restarted from step 1 -- with no checkpoint to resume from,
    the grant paid for 46% of a run twice and kept none of it. A cap is a deadline; preemption is
    an unpredictable kill. Both need checkpoints, and only the first used to get them.
    """
    lane = LANES["modal-a100"]
    assert lane.session_cap_hours is None and lane.preemptible is True
    resolution = resolve(_small_config(), "modal-a100", corpus_rows=11_272)
    assert resolution.save_steps is not None, "a preemptible lane must checkpoint"
    assert resolution.save_steps > 0


def test_exceeding_the_weekly_budget_is_a_warning_not_a_refusal() -> None:
    """It fits the session but there is no second attempt this week -- the operator decides."""

    resolution = resolve(
        _small_config(), "kaggle-t4x2", corpus_rows=900_000, resume_from="checkpoint-1"
    )
    assert any("weekly budget" in warning for warning in resolution.warnings)


# ── the cross-lane confound is recorded, not hidden ─────────────────────────────────────


def test_a_kaggle_resolution_warns_that_its_result_is_not_comparable() -> None:
    resolution = resolve(_small_config(), "kaggle-p100", corpus_rows=500)
    assert resolution.precision == "fp16"
    assert any("NOT numerically comparable" in warning for warning in resolution.warnings)
    assert any("refuse the comparison" in warning for warning in resolution.warnings)


def test_the_local_lane_carries_no_comparability_warning() -> None:
    resolution = resolve(_small_config(), "local-rtx5080", corpus_rows=500)
    assert not any("NOT numerically comparable" in warning for warning in resolution.warnings)


def test_the_serialised_resolution_carries_lane_and_precision() -> None:
    """The gate reads these back to refuse a confounded comparison."""

    payload = resolve(_small_config(), "kaggle-p100", corpus_rows=500).to_dict()
    assert payload["lane"] == "kaggle-p100"
    assert payload["precision"] == "fp16"
    assert payload["session_cap_hours"] == 12.0


def test_the_wall_clock_estimate_scales_with_the_corpus() -> None:
    small = resolve(_small_config(), "local-rtx5080", corpus_rows=1_000)
    large = resolve(_small_config(), "local-rtx5080", corpus_rows=10_000)
    assert large.estimated_hours > small.estimated_hours


def test_the_faster_lane_estimates_a_shorter_run() -> None:
    kaggle = resolve(_small_config(), "kaggle-p100", corpus_rows=1_000)
    modal = resolve(_small_config(), "modal-a100", corpus_rows=1_000)
    assert modal.estimated_hours < kaggle.estimated_hours


def test_the_gated_corpus_warning_survives_into_the_resolution() -> None:
    """fine_tune.plan already warns; the lane layer must not swallow it."""

    config = _small_config()
    config.dataset_id = "expguardmix"
    resolution = resolve(config, "local-rtx5080", corpus_rows=500)
    assert any("GATED" in warning for warning in resolution.warnings)
    assert any("research-only" in warning for warning in resolution.warnings)
