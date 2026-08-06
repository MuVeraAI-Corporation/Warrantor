"""Tests for comply-gate: config parser, gate evaluation, override rules, pipeline."""

from __future__ import annotations

import pytest

from comply_gate import (
    ComplyGateConfig,
    EvidenceProviders,
    GateConfig,
    GateStatus,
    GateType,
    Override,
    OverrideError,
    apply_override,
    evaluate_gate,
    parse_config,
    run_pipeline,
)


SAMPLE_YAML = """\
version: "1"
require_approvers: 2
override_ttl_hours: 24
gates:
  - type: test-coverage
    enabled: true
    threshold: 0.8
  - type: sbom-present
    enabled: true
    path: sbom.spdx.json
  - type: eval-passed
    enabled: true
  - type: disclosure-filed
    enabled: true
"""


# ---------- parse_config ----------
def test_parse_config_reads_top_level_fields() -> None:
    cfg = parse_config(SAMPLE_YAML)
    assert cfg.version == "1"
    assert cfg.require_approvers == 2
    assert cfg.override_ttl_hours == 24


def test_parse_config_reads_all_four_gates() -> None:
    cfg = parse_config(SAMPLE_YAML)
    types = [g.type for g in cfg.gates]
    assert types == [
        GateType.TEST_COVERAGE,
        GateType.SBOM_PRESENT,
        GateType.EVAL_PASSED,
        GateType.DISCLOSURE_FILED,
    ]
    cov = cfg.gate(GateType.TEST_COVERAGE)
    assert cov is not None and cov.threshold == 0.8


def test_parse_config_handles_disabled_gates() -> None:
    yaml = """\
gates:
  - type: test-coverage
    enabled: false
    threshold: 0.9
"""
    cfg = parse_config(yaml)
    assert cfg.gate(GateType.TEST_COVERAGE).enabled is False


def test_parse_config_defaults_when_empty() -> None:
    cfg = parse_config("")
    assert cfg.gates == []
    assert cfg.require_approvers == 2  # default


# ---------- evaluate_gate ----------
def test_test_coverage_passes_when_above_threshold() -> None:
    gate = GateConfig(GateType.TEST_COVERAGE, threshold=0.8)
    ev = EvidenceProviders(coverage=lambda: 0.9)
    result = evaluate_gate(gate, ev)
    assert result.status == GateStatus.PASS
    assert result.detail["coverage"] == 0.9


def test_test_coverage_fails_when_below_threshold() -> None:
    gate = GateConfig(GateType.TEST_COVERAGE, threshold=0.8)
    ev = EvidenceProviders(coverage=lambda: 0.5)
    result = evaluate_gate(gate, ev)
    assert result.status == GateStatus.FAIL


def test_sbom_present_uses_path() -> None:
    gate = GateConfig(GateType.SBOM_PRESENT, path="custom.spdx.json")
    seen: list[str] = []

    def exists(p: str) -> bool:
        seen.append(p)
        return True

    result = evaluate_gate(gate, EvidenceProviders(file_exists=exists))
    assert result.status == GateStatus.PASS
    assert seen == ["custom.spdx.json"]


def test_eval_passed_gate_wires_provider() -> None:
    gate = GateConfig(GateType.EVAL_PASSED)
    assert evaluate_gate(gate, EvidenceProviders(eval_passed=lambda: True)).status == GateStatus.PASS
    assert evaluate_gate(gate, EvidenceProviders(eval_passed=lambda: False)).status == GateStatus.FAIL


def test_disclosure_filed_gate_defaults_path() -> None:
    gate = GateConfig(GateType.DISCLOSURE_FILED)
    result = evaluate_gate(gate, EvidenceProviders(file_exists=lambda p: p == "DISCLOSURE.md"))
    assert result.status == GateStatus.PASS


def test_disabled_gate_returns_skipped() -> None:
    gate = GateConfig(GateType.TEST_COVERAGE, enabled=False, threshold=0.99)
    result = evaluate_gate(gate, EvidenceProviders(coverage=lambda: 0.0))
    assert result.status == GateStatus.SKIPPED


# ---------- apply_override ----------
def test_override_requires_two_distinct_approvers() -> None:
    failing = evaluate_gate(
        GateConfig(GateType.TEST_COVERAGE, threshold=0.99),
        EvidenceProviders(coverage=lambda: 0.1),
    )
    with pytest.raises(OverrideError):
        apply_override(
            failing,
            Override(GateType.TEST_COVERAGE, reason="hotfix", approvers=["alice"]),
            require_approvers=2,
        )


def test_override_succeeds_with_two_approvers() -> None:
    failing = evaluate_gate(
        GateConfig(GateType.TEST_COVERAGE, threshold=0.99),
        EvidenceProviders(coverage=lambda: 0.1),
    )
    overridden = apply_override(
        failing,
        Override(GateType.TEST_COVERAGE, reason="hotfix", approvers=["alice", "bob"]),
        require_approvers=2,
    )
    assert overridden.status == GateStatus.OVERRIDE_APPLIED
    assert overridden.passed


def test_override_rejects_passing_gate() -> None:
    passing = evaluate_gate(
        GateConfig(GateType.TEST_COVERAGE, threshold=0.1),
        EvidenceProviders(coverage=lambda: 0.9),
    )
    with pytest.raises(OverrideError):
        apply_override(
            passing,
            Override(GateType.TEST_COVERAGE, reason="x", approvers=["a", "b"]),
        )


def test_override_rejects_empty_reason() -> None:
    failing = evaluate_gate(
        GateConfig(GateType.TEST_COVERAGE, threshold=0.99),
        EvidenceProviders(coverage=lambda: 0.1),
    )
    with pytest.raises(OverrideError):
        apply_override(
            failing,
            Override(GateType.TEST_COVERAGE, reason="  ", approvers=["a", "b"]),
        )


# ---------- run_pipeline ----------
def test_pipeline_fails_when_any_gate_fails() -> None:
    cfg = parse_config(SAMPLE_YAML)
    ev = EvidenceProviders(
        coverage=lambda: 0.5,  # below 0.8
        file_exists=lambda p: True,
        eval_passed=lambda: True,
    )
    report = run_pipeline(cfg, ev)
    assert not report.passed
    assert len(report.failed_gates) == 1
    assert report.failed_gates[0].gate_type == GateType.TEST_COVERAGE


def test_pipeline_passes_when_all_gates_pass() -> None:
    cfg = parse_config(SAMPLE_YAML)
    ev = EvidenceProviders(
        coverage=lambda: 0.9,
        file_exists=lambda p: True,
        eval_passed=lambda: True,
    )
    report = run_pipeline(cfg, ev)
    assert report.passed
    assert report.failed_gates == []
