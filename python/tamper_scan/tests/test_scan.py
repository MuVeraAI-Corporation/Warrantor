"""Tests for tamper_scan: the four analyzers + aggregate scan."""

from __future__ import annotations

import json

import pytest

from tamper_scan import (
    FindingType,
    Severity,
    TensorStats,
    scan,
    scan_backdoor_patterns,
    scan_fine_tune,
    scan_neuron_pruning,
    scan_weight_distribution,
)
from tamper_scan.cli import main


def test_tensor_stats_baseline() -> None:
    s = TensorStats.from_weights("w", [1.0, 2.0, 3.0, 4.0, 5.0])
    assert s.name == "w"
    assert s.mean == pytest.approx(3.0)
    assert s.min_val == 1.0
    assert s.max_val == 5.0
    assert s.sparsity == 0.0


def test_tensor_stats_sparsity() -> None:
    s = TensorStats.from_weights("w", [0.0, 0.0, 0.0, 1.0])
    assert s.sparsity == pytest.approx(0.75)


def test_backdoor_detector_flags_high_magnitude() -> None:
    findings = scan_backdoor_patterns({"layer1": [0.1, -0.2, 50.0, 0.0, -0.1]})
    assert len(findings) == 1
    assert findings[0].type is FindingType.BACKDOOR_PATTERN
    assert findings[0].severity is Severity.HIGH


def test_backdoor_detector_clean_tensor_no_finding() -> None:
    findings = scan_backdoor_patterns({"layer1": [0.1, -0.2, 0.3]})
    assert findings == []


def test_weight_distribution_flags_outliers() -> None:
    baseline = {"w": TensorStats.from_weights("w", [0.0, 0.1, 0.2, 0.1, 0.0])}
    # Inject many outliers in the subject.
    subject = {"w": TensorStats.from_weights("w", [0.0, 0.1, 5.0, 5.0, 0.0])}
    findings = scan_weight_distribution(baseline, subject)
    types = [f.type for f in findings]
    assert FindingType.WEIGHT_DISTRIBUTION_ANOMALY in types


def test_neuron_pruning_flags_high_sparsity() -> None:
    baseline = {"w": TensorStats.from_weights("w", [0.0, 1.0, 2.0, 3.0])}  # sparsity 0.25
    subject = {"w": TensorStats.from_weights("w", [0.0, 0.0, 0.0, 0.0, 0.0, 1.0])}  # sparsity ~0.83
    findings = scan_neuron_pruning(baseline, subject)
    assert any(f.type is FindingType.NEURON_PRUNING for f in findings)


def test_fine_tune_detector_flags_dissimilar_tensors() -> None:
    base = {"w": [1.0, 0.0, 0.0, 0.0]}
    subject = {"w": [0.0, 1.0, 0.0, 0.0]}  # orthogonal → cosine ~ 0
    findings = scan_fine_tune(base, subject)
    assert len(findings) == 1
    assert findings[0].type is FindingType.FINE_TUNE_DETECTED


def test_fine_tune_detector_clean_no_finding() -> None:
    base = {"w": [1.0, 1.0]}
    subject = {"w": [1.0, 1.0]}  # identical → cosine 1.0
    findings = scan_fine_tune(base, subject)
    assert findings == []


def test_scan_aggregates_all_analyzers() -> None:
    baseline = {"w": [0.0, 0.1, 0.2, 0.1, 0.0, 0.3, 0.2, 0.1]}
    subject = {"w": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 25.0]}
    report = scan(baseline, subject)
    types = {f.type for f in report.findings}
    # Should hit at least backdoor + neuron pruning (high sparsity + high magnitude).
    assert FindingType.BACKDOOR_PATTERN in types
    assert FindingType.NEURON_PRUNING in types
    assert len(report.critical_or_high) >= 1


def test_scan_without_baseline_still_runs_backdoor() -> None:
    report = scan(None, {"w": [100.0, 0.0, 0.0]})
    assert any(f.type is FindingType.BACKDOOR_PATTERN for f in report.findings)


def test_report_to_dict_round_trips() -> None:
    report = scan(None, {"w": [100.0]})
    d = report.to_dict()
    assert d["finding_count"] >= 1
    assert isinstance(d["findings"], list)
    assert "type" in d["findings"][0]


def test_cli_emits_report_and_exits_nonzero_on_high(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> int | None:
    subject = {"w": [100.0, 0.0, 0.0]}
    p = tmp_path / "subj.json"
    p.write_text(json.dumps(subject), encoding="utf-8")
    rc = main(["--subject", str(p)])
    assert rc == 1  # HIGH finding → exit 1
    out = json.loads(capsys.readouterr().out)
    assert out["finding_count"] >= 1
    assert out["critical_or_high"] >= 1
    return rc


def test_cli_clean_subject_exits_zero(tmp_path, capsys: pytest.CaptureFixture[str]) -> int | None:
    p = tmp_path / "subj.json"
    p.write_text(json.dumps({"w": [0.1, 0.2, 0.3]}), encoding="utf-8")
    rc = main(["--subject", str(p)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["finding_count"] == 0
    return rc
