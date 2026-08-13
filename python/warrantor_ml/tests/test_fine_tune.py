"""Fine-tuning plan, VRAM arithmetic, and the promise to fail loudly without a GPU.

The estimator tests pin the arithmetic against envelopes measured on real hardware rather than
against whatever the code currently returns. If a constant is edited, these tests are the thing
that notices.
"""

from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from warrantor_ml import fine_tune as ft

# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


def test_the_primary_base_is_qwen3guard_not_llama_guard() -> None:
    """The corrected model choice. Qwen Guard 4B leads recall at 83.97%."""

    default = ft.FineTuneConfig()
    assert default.profile_key == "qwen3guard-gen-4b"
    assert default.profile().repo_id == "Qwen/Qwen3Guard-Gen-4B"
    assert "llama" not in json.dumps(list(ft.PROFILES)).lower()


def test_profiles_record_their_licences() -> None:
    assert ft.PROFILES["qwen3guard-gen-4b"].licence == "Apache-2.0"
    assert ft.PROFILES["deberta-v3-large-injection"].licence == "MIT"


def test_deberta_carries_its_512_token_ceiling() -> None:
    profile = ft.PROFILES["deberta-v3-large-injection"]
    assert profile.max_position_embeddings == 512
    assert any("sliding window" in note for note in profile.notes)


def test_kv_cache_arithmetic_matches_the_measured_figure() -> None:
    """36 layers x 8 KV heads x 128 head_dim, fp16 -> 147,456 bytes/token."""

    for key in ("qwen3guard-gen-4b", "qwen3guard-gen-8b"):
        assert ft.PROFILES[key].kv_bytes_per_token == 147_456
    # 0.141 MiB/token -> 32K context is ~4.5 GiB of KV cache alone.
    per_token_mib = 147_456 / 1024**2
    assert per_token_mib == pytest.approx(0.1406, abs=0.001)
    assert pytest.approx(4.5, abs=0.1) == 32_768 * 147_456 / 1024**3


def test_unknown_profile_lists_what_exists() -> None:
    with pytest.raises(ValueError, match="unknown profile"):
        ft.FineTuneConfig(profile_key="llama-guard-3").profile()


def test_unknown_dtype_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown dtype"):
        ft.bytes_per_parameter("fp8")


# ---------------------------------------------------------------------------
# VRAM estimates, pinned to measured envelopes
# ---------------------------------------------------------------------------


def test_4b_qlora_lands_in_the_measured_7_to_9_gib_band() -> None:
    estimate = ft.estimate_training_vram_gib(
        ft.PROFILES["qwen3guard-gen-4b"],
        technique="qlora",
        base_dtype="nf4",
        sequence_length=2048,
        batch_size=2,
        gradient_checkpointing=True,
    )
    assert 7.0 <= estimate.total_gib <= 9.0
    # NF4 base is ~2.8 GiB, which is what makes the whole lane fit.
    assert estimate.components_gib["base_weights"] == pytest.approx(2.8, abs=0.2)


def test_deberta_full_fine_tune_lands_in_the_measured_9_to_11_gib_band() -> None:
    """The one model in this plan that fully fine-tunes on a 16 GB laptop card."""

    estimate = ft.estimate_training_vram_gib(
        ft.PROFILES["deberta-v3-large-injection"],
        technique="full",
        sequence_length=512,
        batch_size=16,
        gradient_checkpointing=False,
    )
    assert 9.0 <= estimate.total_gib <= 11.0


def test_8b_qlora_lands_in_the_measured_9_to_11_gib_band() -> None:
    estimate = ft.estimate_training_vram_gib(
        ft.PROFILES["qwen3guard-gen-8b"],
        technique="qlora",
        base_dtype="nf4",
        sequence_length=2048,
        batch_size=1,
        gradient_checkpointing=True,
    )
    assert 9.0 <= estimate.total_gib <= 11.0


def test_8b_bf16_inference_does_not_fit_a_16gb_card() -> None:
    """Weights alone are 15.25 GiB against 15,055 MiB free. Definitively out."""

    estimate = ft.estimate_inference_vram_gib(
        ft.PROFILES["qwen3guard-gen-8b"], weight_dtype="bf16", context_tokens=0
    )
    assert estimate.components_gib["weights"] > 15.0
    assert not estimate.fits_within(14.7)


def test_4b_q4_at_full_context_is_comfortable() -> None:
    estimate = ft.estimate_inference_vram_gib(
        ft.PROFILES["qwen3guard-gen-4b"], weight_dtype="nf4", context_tokens=32_768
    )
    assert estimate.fits_within(14.7)
    assert estimate.total_gib < 10.0


def test_gradient_checkpointing_reduces_activation_memory() -> None:
    profile = ft.PROFILES["qwen3guard-gen-4b"]
    with_ckpt = ft.estimate_training_vram_gib(profile, gradient_checkpointing=True)
    without = ft.estimate_training_vram_gib(profile, gradient_checkpointing=False)
    assert with_ckpt.components_gib["activations"] < without.components_gib["activations"]


def test_estimate_components_sum_to_the_total() -> None:
    estimate = ft.estimate_training_vram_gib(ft.PROFILES["qwen3guard-gen-4b"])
    assert sum(estimate.components_gib.values()) == pytest.approx(estimate.total_gib, abs=0.01)


# ---------------------------------------------------------------------------
# Precision selection -- the Kaggle caveat
# ---------------------------------------------------------------------------


def test_t4_and_p100_get_fp16_with_a_calibration_warning() -> None:
    for capability in ((7, 5), (6, 0)):  # T4 sm_75, P100 sm_60
        precision, reason = ft.select_precision(capability)
        assert precision == "fp16"
        assert "NO bf16" in reason
        assert "calibration" in reason


def test_ampere_and_blackwell_get_bf16() -> None:
    for capability in ((8, 0), (8, 9), (12, 0)):
        precision, _reason = ft.select_precision(capability)
        assert precision == "bf16"


def test_accelerator_bf16_property_tracks_compute_capability() -> None:
    turing = ft.Accelerator("T4", 15.0, 14.5, (7, 5), 2, "2.7.0")
    blackwell = ft.Accelerator("RTX 5080", 15.9, 14.7, (12, 0), 1, "2.7.0")
    assert turing.supports_bf16 is False
    assert blackwell.supports_bf16 is True


# ---------------------------------------------------------------------------
# Failing loudly
# ---------------------------------------------------------------------------


def test_missing_torch_raises_with_install_instructions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "torch":
            raise ImportError("No module named 'torch'")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ft.MissingTrainingDependenciesError) as excinfo:
        ft.detect_accelerator()
    message = str(excinfo.value)
    assert "pip install" in message
    assert "sm_120" in message  # the Blackwell wheel-matrix trap


def test_no_cuda_device_raises_and_never_falls_back_to_cpu(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeCuda:
        @staticmethod
        def is_available() -> bool:
            return False

    class FakeTorch:
        cuda = FakeCuda()
        __version__ = "2.7.0"

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "torch":
            return FakeTorch()
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ft.NoSuitableAcceleratorError) as excinfo:
        ft.detect_accelerator()
    message = str(excinfo.value)
    assert "NO CPU fallback" in message
    assert "Kaggle" in message
    assert "--dry-run" in message


def test_insufficient_vram_refuses_before_starting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ft,
        "detect_accelerator",
        lambda: ft.Accelerator("Tiny GPU", 6.0, 4.0, (8, 6), 1, "2.7.0"),
    )
    with pytest.raises(ft.NoSuitableAcceleratorError) as excinfo:
        ft.require_accelerator(9.0)
    message = str(excinfo.value)
    assert "4.00 GiB free" in message
    assert "OOM three hours in" in message


def test_sufficient_vram_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    accelerator = ft.Accelerator("RTX 5080", 15.9, 14.7, (12, 0), 1, "2.7.0")
    monkeypatch.setattr(ft, "detect_accelerator", lambda: accelerator)
    assert ft.require_accelerator(9.0) is accelerator


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


def test_plan_needs_no_gpu_and_no_torch() -> None:
    resolved = ft.plan(ft.FineTuneConfig())
    assert resolved.estimate.total_gib > 0
    assert resolved.minimum_free_gib > resolved.estimate.total_gib
    assert resolved.effective_batch_size == 16


def test_plan_warns_about_gated_corpora() -> None:
    warnings = " ".join(ft.plan(ft.FineTuneConfig(dataset_id="wildguardmix")).warnings)
    assert "GATED" in warnings
    assert "401" in warnings


def test_plan_warns_about_the_expguardmix_licence_conflict() -> None:
    warnings = " ".join(ft.plan(ft.FineTuneConfig(dataset_id="expguardmix")).warnings)
    assert "research-only" in warnings
    assert "counsel" in warnings


def test_plan_warns_when_sequence_length_exceeds_the_deberta_ceiling() -> None:
    resolved = ft.plan(
        ft.FineTuneConfig(
            profile_key="deberta-v3-large-injection", sequence_length=2048, technique="full"
        )
    )
    warnings = " ".join(resolved.warnings)
    assert "max_position_embeddings" in warnings
    assert "sliding window" in warnings


def test_plan_warns_that_a_4b_full_fine_tune_has_no_free_tier() -> None:
    warnings = " ".join(ft.plan(ft.FineTuneConfig(technique="full")).warnings)
    assert "no free tier" in warnings.lower() or "Not available on any free tier" in warnings


def test_plan_serialises_to_json() -> None:
    document = ft.plan(ft.FineTuneConfig()).to_dict()
    assert json.dumps(document)
    assert document["profile"]["repo_id"] == "Qwen/Qwen3Guard-Gen-4B"
    assert document["vram_estimate_gib"]["components"]["base_weights"] > 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_dry_run_succeeds_without_a_gpu(capsys: pytest.CaptureFixture[str]) -> None:
    assert ft.main(["--dry-run"]) == 0
    printed = capsys.readouterr().out
    assert "PLAN ONLY" in printed
    assert "no training was performed" in printed
    assert "VRAM estimate" in printed


def test_cli_dry_run_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert ft.main(["--dry-run", "--json", "--profile", "deberta-v3-large-injection"]) == 0
    lines = capsys.readouterr().out
    document = json.loads(lines[: lines.rindex("}") + 1])
    assert document["profile"]["repo_id"] == "microsoft/deberta-v3-large"


def test_cli_without_dry_run_aborts_loudly_when_there_is_no_gpu(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def refuse(_minimum: float) -> ft.Accelerator:
        raise ft.NoSuitableAcceleratorError(ft._NO_GPU_MESSAGE)

    monkeypatch.setattr(ft, "require_accelerator", refuse)
    exit_code = ft.main(["--output-dir", str(tmp_path / "out")])
    assert exit_code == 2
    assert "TRAINING ABORTED" in capsys.readouterr().err
    # And nothing was written -- an aborted run leaves no artifact to mistake for a real one.
    assert not (tmp_path / "out").exists()
