"""Publishing an adapter: refuse before converting, and pin what the error messages hide.

The two assertions worth the most here are about Ollama's behaviour, because both were found by
running it and neither is visible from its output: it takes a GGUF adapter and refuses a
safetensors one, and it resolves ADAPTER relative to the Modelfile rather than the shell.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from warrantor_ml.publish import (
    PublishRefused,
    build_modelfile,
    candidate_model_name,
    convert_command,
    plan_publish,
    publish,
)

BASE = "hf.co/mradermacher/Qwen3Guard-Gen-0.6B-GGUF:Q4_K_M"


def _adapter(tmp_path: Path, *, config: bool = True, weights: bool = True) -> Path:
    directory = tmp_path / "adapter"
    directory.mkdir()
    if config:
        (directory / "adapter_config.json").write_text("{}", encoding="utf-8")
    if weights:
        (directory / "adapter_model.safetensors").write_bytes(b"\x00")
    return directory


def _snapshot(tmp_path: Path, *, config: bool = True) -> Path:
    directory = tmp_path / "base"
    directory.mkdir()
    if config:
        (directory / "config.json").write_text("{}", encoding="utf-8")
    return directory


def test_the_adapter_path_is_written_absolute_into_the_modelfile(tmp_path: Path) -> None:
    """ADAPTER resolves against the Modelfile's directory, not the working directory.

    A relative path that is correct when typed at a shell silently resolves one level deep once
    written into a Modelfile that itself lives in the adapter directory -- which is how
    `./adapters/x` became `adapters/adapters/x`.
    """

    text = build_modelfile(BASE, Path("adapters/run.gguf"))
    adapter_line = next(line for line in text.splitlines() if line.startswith("ADAPTER"))
    assert Path(adapter_line.split(" ", 1)[1]).is_absolute()
    assert text.startswith(f"FROM {BASE}\n")


def test_the_model_tag_carries_the_run_not_only_the_recipe() -> None:
    """A tag naming only the recipe is overwritten by the next run of that recipe.

    An evaluation already recorded against it would then describe a model that no longer exists
    under that name.
    """

    first = candidate_model_name("guard-0.6b-weak-category", "weak-2026-08-13a")
    second = candidate_model_name("guard-0.6b-weak-category", "weak-2026-08-14b")
    assert first != second
    assert "weak-2026-08-13a" in first


def test_an_adapter_without_its_config_is_refused(tmp_path: Path) -> None:
    """Rank, alpha and target modules are read from the config; guessing them is not an option."""

    with pytest.raises(PublishRefused, match="adapter_config.json"):
        plan_publish(
            _adapter(tmp_path, config=False),
            _snapshot(tmp_path),
            BASE,
            "guard-0.6b-weak-category",
            "run",
            tmp_path / "work",
        )


def test_a_repo_id_passed_as_the_base_is_refused_with_the_reason(tmp_path: Path) -> None:
    """convert_lora_to_gguf.py wants a directory and fails on the literal repo-id string."""

    with pytest.raises(PublishRefused, match="repo id"):
        plan_publish(
            _adapter(tmp_path),
            _snapshot(tmp_path, config=False),
            BASE,
            "guard-0.6b-weak-category",
            "run",
            tmp_path / "work",
        )


def test_the_conversion_keeps_the_adapter_unquantised(tmp_path: Path) -> None:
    """The base supplies the quantisation. Quantising the delta too compounds two roundings
    that the baseline's Q4_K_M measurement never saw."""

    plan = plan_publish(
        _adapter(tmp_path),
        _snapshot(tmp_path),
        BASE,
        "guard-0.6b-weak-category",
        "run",
        tmp_path / "work",
    )
    command = convert_command(plan, Path("convert_lora_to_gguf.py"))
    assert "--outtype" in command
    assert command[command.index("--outtype") + 1] == "f16"
    # The base is passed as a directory, which is the whole point of the refusal above.
    assert command[command.index("--base") + 1] == str(plan.base_snapshot)


def test_the_converter_runs_under_this_interpreter_by_default(tmp_path: Path) -> None:
    """"python" resolves to whatever is first on PATH, which need not be the one running this.

    The converter needs torch, safetensors and gguf. On a machine where those live in a separate
    venv the failure is an ImportError seconds into a conversion, not a refusal -- and the run
    that produced the adapter is already spent by then.
    """

    plan = plan_publish(
        _adapter(tmp_path),
        _snapshot(tmp_path),
        BASE,
        "guard-0.6b-weak-category",
        "run",
        tmp_path / "work",
    )
    assert convert_command(plan, Path("c.py"))[0] == sys.executable
    assert convert_command(plan, Path("c.py"), "/other/venv/bin/python")[0] == "/other/venv/bin/python"


def test_neither_a_converter_nor_a_gguf_is_refused(tmp_path: Path) -> None:
    """Registering without an adapter yields a tag that scores as the untuned base.

    That is the worst outcome available here: a candidate model name whose numbers are the
    baseline's, compared against the baseline, reported as a fair test of the fine-tune.
    """

    plan = plan_publish(
        _adapter(tmp_path),
        _snapshot(tmp_path),
        BASE,
        "guard-0.6b-weak-category",
        "run",
        tmp_path / "work",
    )
    with pytest.raises(PublishRefused, match="--converter or --gguf"):
        publish(plan)


def test_a_prebuilt_gguf_that_is_not_there_is_refused(tmp_path: Path) -> None:
    """The split-environment path must not be the one that skips the existence check."""

    plan = plan_publish(
        _adapter(tmp_path),
        _snapshot(tmp_path),
        BASE,
        "guard-0.6b-weak-category",
        "run",
        tmp_path / "work",
    )
    with pytest.raises(PublishRefused, match="no GGUF adapter"):
        publish(plan, prebuilt_gguf=tmp_path / "absent.gguf")


def test_planning_needs_no_ollama_on_the_machine(tmp_path: Path, monkeypatch) -> None:
    """Planning is pure, and CI has no Ollama.

    These tests passed locally only because Ollama happens to be installed on the machine that
    wrote them, and failed in CI where it is not. The fix was not to mock the check but to move
    it: `plan_publish` reads the filesystem it was given and returns a value, so `--plan-only`
    works on a build box, and `publish` requires the binary before it spends anything.
    """

    monkeypatch.setattr("warrantor_ml.publish.shutil.which", lambda _name: None)

    plan = plan_publish(
        _adapter(tmp_path),
        _snapshot(tmp_path),
        BASE,
        "guard-0.6b-weak-category",
        "run",
        tmp_path / "work",
    )
    assert plan.model_name


def test_a_caller_mistake_is_named_before_a_missing_ollama(tmp_path: Path, monkeypatch) -> None:
    """"You passed neither --converter nor --gguf" is actionable anywhere.

    "ollama is not on PATH" is a fact about one machine, and reporting it first would mask the
    mistake the caller can actually fix.
    """

    monkeypatch.setattr("warrantor_ml.publish.shutil.which", lambda _name: None)

    plan = plan_publish(
        _adapter(tmp_path),
        _snapshot(tmp_path),
        BASE,
        "guard-0.6b-weak-category",
        "run",
        tmp_path / "work",
    )
    with pytest.raises(PublishRefused, match="--converter or --gguf"):
        publish(plan)
