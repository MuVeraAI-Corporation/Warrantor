"""Tests for metr-bridge: adapter, exporter, risk bridge, verifier."""

from __future__ import annotations

import json

from metr_bridge import (
    AgentStep,
    AumOSFinding,
    AumOSRiskReport,
    IndependentVerifier,
    METREvalAdapter,
    METRTaskSpec,
    RiskReportBridge,
    SafeEvalPipeline,
    TranscriptExporter,
    new_task_id,
)


# ---------- METREvalAdapter ----------
def test_adapter_translates_evaluations_into_stages() -> None:
    spec = METRTaskSpec(
        task_id="t-1",
        description="demo",
        max_steps=30,
        success_threshold=0.9,
        evaluations=[
            {"name": "safety", "metric": "toxicity_rate", "threshold": 0.05, "weight": 1.0},
            {"name": "goal", "metric": "completion", "threshold": 0.9, "weight": 2.0},
        ],
    )
    pipeline = METREvalAdapter().adapt(spec, target="model://aumos-7b")
    assert pipeline.target == "model://aumos-7b"
    assert pipeline.metadata["task_id"] == "t-1"
    assert pipeline.metadata["max_steps"] == 30
    # 2 evaluations + 1 final gate
    assert len(pipeline.stages) == 3
    assert pipeline.stages[-1]["type"] == "gate"
    assert pipeline.stages[0]["name"] == "safety"


def test_adapter_preserves_success_threshold_in_final_gate() -> None:
    spec = METRTaskSpec(task_id="t", description="d", success_threshold=0.75)
    pipeline = METREvalAdapter().adapt(spec)
    gate = pipeline.stages[-1]
    assert gate["threshold"] == 0.75


# ---------- TranscriptExporter ----------
def test_exporter_serializes_to_jsonl() -> None:
    steps = [
        AgentStep(step=1, role="user", content="hello"),
        AgentStep(step=2, role="assistant", content="hi", tool="echo"),
    ]
    blob = TranscriptExporter().export(steps)
    text = blob.decode("utf-8")
    lines = [l for l in text.splitlines() if l]
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    assert rec0["role"] == "user"
    assert rec0["step"] == 1
    rec1 = json.loads(lines[1])
    assert rec1["tool"] == "echo"


def test_exporter_lines_returns_dicts_in_order() -> None:
    steps = [AgentStep(step=i, role="assistant", content=f"c{i}") for i in range(5)]
    out = TranscriptExporter().export_lines(steps)
    assert [r["step"] for r in out] == [0, 1, 2, 3, 4]


# ---------- RiskReportBridge ----------
def test_risk_bridge_sorts_by_severity_and_adds_tags() -> None:
    report = AumOSRiskReport(
        target="model://aumos-7b",
        findings=[
            AumOSFinding(rule_id="LOW1", severity="low", message="m1", cwe="CWE-123"),
            AumOSFinding(rule_id="CRIT1", severity="critical", message="m2", atlas="AML.T0051"),
            AumOSFinding(rule_id="HIGH1", severity="high", message="m3", cwe="CWE-456"),
        ],
    )
    out = RiskReportBridge().to_metr(report)
    assert out["schema"] == "metr.risk.v1"
    sev_order = [r["severity"] for r in out["findings"]]
    assert sev_order == ["critical", "high", "low"]
    assert out["summary"]["critical"] == 1
    tags_crit = out["findings"][0]["tags"]
    assert "AML.T0051" in tags_crit


def test_risk_bridge_handles_empty_report() -> None:
    out = RiskReportBridge().to_metr(AumOSRiskReport(target="x"))
    assert out["findings"] == []
    assert out["summary"] == {}


# ---------- IndependentVerifier ----------
def test_verifier_marks_reproducible_when_within_tolerance() -> None:
    class FakeRunner:
        def run(self, pipeline: SafeEvalPipeline, seed: int) -> float:
            # ignore seed -> always 0.9
            return 0.9

    v = IndependentVerifier(runner=FakeRunner(), tolerance=0.05, secondary_seed=7)
    result = v.verify(SafeEvalPipeline(target="m"), primary_seed=1)
    assert result.reproduced
    assert result.delta == 0.0


def test_verifier_flags_non_reproducible_eval() -> None:
    class WobblyRunner:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, pipeline: SafeEvalPipeline, seed: int) -> float:
            self.calls += 1
            return 0.9 if self.calls == 1 else 0.5

    v = IndependentVerifier(runner=WobblyRunner(), tolerance=0.05)
    result = v.verify(SafeEvalPipeline(target="m"), primary_seed=1)
    assert not result.reproduced
    assert result.delta > 0.05


def test_default_deterministic_runner_is_seed_dependent() -> None:
    v = IndependentVerifier(tolerance=0.0, secondary_seed=2)
    r = v.verify(SafeEvalPipeline(target="model://aumos-7b"), primary_seed=1)
    # different seeds with the default runner -> different scores -> not reproduced at tol=0
    assert r.primary_score != r.secondary_score


# ---------- new_task_id ----------
def test_new_task_id_has_prefix_and_suffix() -> None:
    tid = new_task_id("metr")
    assert tid.startswith("metr-")
    assert len(tid.split("-", 1)[1]) == 8
