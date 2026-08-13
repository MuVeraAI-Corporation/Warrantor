"""The generated lane runners: they must compile, and they must keep the three refusals.

Every one of these scripts lands under ``ml/``, where ``tools/ci/run_python_checks.py`` never
looks -- no ruff, no pytest. Generating them from linted package code is what puts them back
inside the gate, and these tests are the gate.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from warrantor_ml.lane_export import (
    GATED_DATA_MESSAGE,
    render_kaggle_script,
    render_modal_entrypoint,
    script_digest,
)
from warrantor_ml.lanes import resolve
from warrantor_ml.recipes import get_recipe

_RECIPE = get_recipe("guard-0.6b-weak-category")


def _kaggle_text() -> str:
    resolution = resolve(_RECIPE.config, "kaggle-t4x2", 5_000, resume_from="checkpoint")
    return render_kaggle_script(_RECIPE, resolution)


def _modal_text() -> str:
    resolution = resolve(_RECIPE.config, "modal-a100", 5_000)
    return render_modal_entrypoint(_RECIPE, resolution)


# ── they are valid Python ───────────────────────────────────────────────────────────────


def test_the_generated_kaggle_script_compiles() -> None:
    compile(_kaggle_text(), "train_kaggle.py", "exec")


def test_the_generated_modal_entrypoint_compiles() -> None:
    compile(_modal_text(), "train_modal.py", "exec")


def test_neither_generator_imports_modal_into_this_package() -> None:
    """modal is an optional extra and CI does not install it. This module renders text."""

    import warrantor_ml.lane_export as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "modal" not in imported
    assert "torch" not in imported


# ── the three behaviours that must survive any edit ─────────────────────────────────────


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_no_cpu_fallback_survives_generation(render) -> None:  # type: ignore[no-untyped-def]
    """A guard fine-tune that quietly runs on CPU produces an artifact nobody can tell apart."""

    text = render()
    assert "NO CPU fallback by design" in text
    assert "raise SystemExit(2)" in text
    assert "def require_cuda" in text


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_the_gated_data_message_survives_generation(render) -> None:  # type: ignore[no-untyped-def]
    text = render()
    assert GATED_DATA_MESSAGE in text
    assert "no anonymous download path" in text


def test_the_fp16_calibration_warning_is_present_on_a_kaggle_lane() -> None:
    """A guard model's product is a calibrated logit, and fp16 loss scaling is where it goes."""

    text = _kaggle_text()
    assert "NO bf16" in text
    assert "CALIBRATED LOGIT" in text
    assert 'PRECISION = "fp16"' in text


def test_the_fp16_warning_is_absent_on_a_bf16_lane() -> None:
    """Printing it where it does not apply teaches people to ignore it."""

    text = _modal_text()
    assert "CALIBRATED LOGIT" not in text
    assert 'PRECISION = "bf16"' in text


# ── the run record binds a result to its recipe, lane and precision ─────────────────────


@pytest.mark.parametrize("render", [_kaggle_text, _modal_text])
def test_the_run_manifest_carries_the_recipe_digest_lane_and_precision(
    render,  # type: ignore[no-untyped-def]
) -> None:
    """Without these three, a result document describes a run nobody can place."""

    text = render()
    body = text.split("RUN_MANIFEST = ", 1)[1].split("\n\nBASE_REPO", 1)[0]
    manifest = json.loads(body)
    assert manifest["recipe_digest"] == _RECIPE.recipe_digest
    assert manifest["lane"] in {"kaggle-t4x2", "modal-a100"}
    assert manifest["precision"] in {"fp16", "bf16"}


def test_the_kaggle_script_carries_a_resume_contract() -> None:
    """A session killed at the 12-hour cap must resume, not restart."""

    text = _kaggle_text()
    assert "--resume-from" in text
    assert "SAVE_STEPS" in text
    assert "resume_from_checkpoint=resume_from" in text


def test_the_generated_header_says_it_is_generated() -> None:
    for text in (_kaggle_text(), _modal_text()):
        assert "GENERATED -- do not edit" in text
        assert "recipes.py" in text


# ── the generators refuse a mismatched lane ─────────────────────────────────────────────


def test_rendering_a_kaggle_script_for_a_non_kaggle_lane_is_refused() -> None:
    """A script that claims the wrong lane produces a run record that lies about it."""

    resolution = resolve(_RECIPE.config, "modal-a100", 5_000)
    with pytest.raises(ValueError, match="Resolve the recipe against a kaggle lane"):
        render_kaggle_script(_RECIPE, resolution)


def test_rendering_a_modal_entrypoint_for_a_kaggle_lane_is_refused() -> None:
    resolution = resolve(_RECIPE.config, "kaggle-p100", 5_000, resume_from="checkpoint")
    with pytest.raises(ValueError, match="resolve against modal-a100"):
        render_modal_entrypoint(_RECIPE, resolution)


def test_the_script_digest_is_stable() -> None:
    assert script_digest(_kaggle_text()) == script_digest(_kaggle_text())
    assert script_digest(_kaggle_text()) != script_digest(_modal_text())


def test_the_modal_entrypoint_ships_the_corpus_rather_than_a_hub_token() -> None:
    """A container that authenticates to the Hub is a container holding a read token.

    The gated-data message still NAMES ``HF_TOKEN`` -- that is how a human is told what to do
    locally. What must be absent is any code that reads it, so the remote container never has
    credentials for a gated corpus in the first place.
    """

    text = _modal_text()
    assert "corpus_bytes" in text
    assert "os.environ" not in text
    assert "hf_hub_download" not in text
    # The message may name the variable; nothing may read it.
    assert 'environ["HF_TOKEN"]' not in text
    assert "environ.get(" not in text
