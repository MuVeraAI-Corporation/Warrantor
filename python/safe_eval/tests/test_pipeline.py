"""Tests for safe_eval: built-in adapters, pipeline orchestration, VEB emission, YAML."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from safe_eval import (
    Metric,
    PipelineSpec,
    StageSpec,
    StageType,
    get_adapter,
    parse_pipeline_yaml,
    register_adapter,
    run_pipeline,
    to_veb,
)
from safe_eval.cli import main


def sample_pipeline() -> PipelineSpec:
    return PipelineSpec(
        target="model://aumos-7b",
        stages=[
            StageSpec(StageType.BENCHMARKS, "benchmarks", {"mock_accuracy": 0.85}),
            StageSpec(StageType.ADVERSARIAL, "adversarial", {"attacks": ["prompt_injection"], "mock_attack_success_rate": 0.05}),
            StageSpec(StageType.SAFETY, "safety"),
            StageSpec(StageType.BIAS, "bias"),
            StageSpec(StageType.RED_TEAM, "red_team"),
        ],
    )


def test_builtin_adapters_registered() -> None:
    for name in ("benchmarks", "adversarial", "safety", "bias", "red_team"):
        assert get_adapter(name) is not None


def test_run_pipeline_executes_every_stage() -> None:
    result = run_pipeline(sample_pipeline())
    assert len(result.stages) == 5
    assert result.ok
    types = {s.stage_type for s in result.stages}
    assert types == {StageType.BENCHMARKS, StageType.ADVERSARIAL, StageType.SAFETY, StageType.BIAS, StageType.RED_TEAM}


def test_run_pipeline_collects_metrics() -> None:
    result = run_pipeline(sample_pipeline())
    metrics = result.all_metrics()
    names = {m.name for m in metrics}
    assert "lm-eval.accuracy" in names  # benchmarks adapter prepends the suite name
    assert "attack_success_rate" in names
    assert "safety.toxicity_rate" in names


def test_unregistered_adapter_produces_error_stage() -> None:
    spec = PipelineSpec(target="m", stages=[StageSpec(StageType.BENCHMARKS, "no-such-adapter")])
    result = run_pipeline(spec)
    assert len(result.stages) == 1
    assert result.stages[0].error is not None
    assert not result.ok


def test_failing_adapter_does_not_abort_pipeline() -> None:
    class BoomAdapter:
        name = "boom"

        def run(self, target, config):  # noqa: ANN001
            raise RuntimeError("kaboom")

    register_adapter(BoomAdapter())
    spec = PipelineSpec(
        target="m",
        stages=[
            StageSpec(StageType.BENCHMARKS, "boom"),
            StageSpec(StageType.SAFETY, "safety"),
        ],
    )
    result = run_pipeline(spec)
    assert not result.ok
    assert result.stages[0].error is not None
    assert result.stages[1].ok  # safety stage still ran


def test_to_veb_emits_bundle() -> None:
    result = run_pipeline(sample_pipeline())
    veb = to_veb(result, corpus_digest="sha256:abc")
    assert veb["model"] == "model://aumos-7b"
    assert veb["corpus_digest"] == "sha256:abc"
    assert any(m["name"].endswith(".accuracy") for m in veb["metrics"])


def test_parse_pipeline_yaml() -> None:
    yaml_text = """
target: model://x
stages:
  - type: benchmarks
    adapter: benchmarks
    config:
      mock_accuracy: 0.9
  - type: safety
    adapter: safety
metadata:
  owner: team-a
"""
    spec = parse_pipeline_yaml(yaml_text)
    assert spec.target == "model://x"
    assert len(spec.stages) == 2
    assert spec.stages[0].type is StageType.BENCHMARKS
    assert spec.stages[0].config["mock_accuracy"] == 0.9
    assert spec.metadata["owner"] == "team-a"


def test_parse_pipeline_yaml_rejects_missing_target() -> None:
    with pytest.raises(ValueError, match="target"):
        parse_pipeline_yaml("stages: []")


def test_cli_runs_yaml_pipeline(tmp_path, capsys: pytest.CaptureFixture[str]) -> int | None:
    yaml_text = """
target: model://cli-test
stages:
  - type: benchmarks
    adapter: benchmarks
  - type: safety
    adapter: safety
"""
    p = tmp_path / "pipe.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    rc = main(["--pipeline", str(p)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["target"] == "model://cli-test"
    assert out["ok"] is True
    return rc


def test_cli_veb_flag(tmp_path, capsys: pytest.CaptureFixture[str]) -> int | None:
    yaml_text = "target: model://veb-test\nstages:\n  - type: benchmarks\n    adapter: benchmarks\n"
    p = tmp_path / "pipe.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    rc = main(["--pipeline", str(p), "--veb"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["veb_id"].startswith("veb:")
    return rc
