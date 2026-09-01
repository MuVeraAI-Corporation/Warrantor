"""Tests for the paired candidate-versus-baseline comparison.

# What these protect

The module exists because a recall delta is not a verdict, and this repository has a recorded
instance of that error: a monotonicity check reported a 0.1867 -> 0.1600 dip as a reversal when a
McNemar on the same data gave **2 worse, 4 better, p = 0.688**. The first test below pins that
historical case, so the implementation is validated against a result the project already knows.

The second thing they protect is the severity check. Every fine-tune measured in this programme
damaged its severity field, and one of them cleared every stated promotion bar while emitting zero
`controversial` verdicts. A comparison module that reported only recall would have called that
adapter a success -- so `VOID` must win over any p-value, and that ordering is asserted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from warrantor_ml.paired_analysis import compare, exact_mcnemar, render


def test_the_historical_case_this_module_exists_for() -> None:
    """2 worse, 4 better reproduces the p = 0.688 already recorded for that comparison.

    Validating against a known project result rather than against a textbook example: if the
    implementation ever drifts, it drifts away from a number somebody already checked.
    """
    assert round(exact_mcnemar(2, 4), 3) == 0.688


def test_no_discordant_pairs_is_no_evidence() -> None:
    """Two models that never disagree provide no evidence either way, and p must say so."""
    assert exact_mcnemar(0, 0) == 1.0


def test_a_large_one_sided_split_is_decisive() -> None:
    """91 against 9 is the observed regression. It must not come back merely 'probably'."""
    assert exact_mcnemar(91, 9) < 1e-9


def test_the_exact_test_is_symmetric() -> None:
    """Direction is carried by the counts, not by the p-value; the test itself is two-sided."""
    assert exact_mcnemar(4, 7) == exact_mcnemar(7, 4)


def test_small_samples_are_not_flattered() -> None:
    """The reason this is exact rather than chi-square.

    With 11 discordant pairs -- a real case in this programme -- the approximation is not
    trustworthy, and a p-value wrong in the permissive direction is how noise becomes a finding.
    A 4/7 split must stay comfortably non-significant.
    """
    assert exact_mcnemar(4, 7) > 0.5


def _write(tmp_path: Path, name: str, samples: list[dict]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"samples": samples}), encoding="utf-8")
    return path


def _sample(sid: str, expected: bool, predicted: bool, severity: str) -> dict:
    return {
        "sample_id": sid,
        "expected_unsafe": expected,
        "predicted_unsafe": predicted,
        "severity": severity,
        "errored": False,
    }


def test_a_lost_severity_class_voids_the_comparison(tmp_path: Path) -> None:
    """The failure mode that passed every stated bar.

    The candidate here has BETTER recall -- it catches an item the baseline misses -- and the
    verdict must still be VOID, because a model that no longer emits a class the baseline emits is
    not the same instrument. If this ever returns 'candidate better', the module has become the
    thing it was written to prevent.
    """
    # Both files keep a `safe` row, so `controversial` is the ONLY class the candidate loses.
    # Without it the fixture also drops `safe` and the assertion below passes for the wrong reason.
    baseline = _write(
        tmp_path,
        "base.json",
        [
            _sample("a", True, True, "unsafe"),
            _sample("b", True, False, "safe"),
            _sample("c", True, True, "controversial"),
            _sample("n", False, False, "safe"),
        ],
    )
    candidate = _write(
        tmp_path,
        "cand.json",
        [
            _sample("a", True, True, "unsafe"),
            _sample("b", True, True, "unsafe"),
            _sample("c", True, True, "unsafe"),
            _sample("n", False, False, "safe"),
        ],
    )
    verdict = compare(candidate, baseline, "flattened")
    assert verdict.candidate_only == 1 and verdict.baseline_only == 0
    assert verdict.severity_classes_lost == {"controversial"}
    assert verdict.verdict.startswith("VOID")
    assert "CLASS LOST" in render(verdict)


def test_a_preserved_severity_field_reports_the_recall_verdict(tmp_path: Path) -> None:
    """The control for the test above: no class lost, so the p-value decides."""
    rows = [_sample(str(i), True, True, "unsafe") for i in range(6)]
    baseline = _write(tmp_path, "base.json", rows + [_sample("x", True, True, "controversial")])
    candidate = _write(tmp_path, "cand.json", rows + [_sample("x", True, False, "controversial")])
    verdict = compare(candidate, baseline, "preserved")
    assert verdict.severity_classes_lost == set()
    assert verdict.verdict == "within noise"


def test_errored_items_are_excluded_rather_than_counted_as_misses(tmp_path: Path) -> None:
    """A backend that was down is a failed measurement, not a guard with poor recall."""
    baseline = _write(tmp_path, "base.json", [_sample("a", True, True, "unsafe")])
    bad = _sample("a", True, False, "safe")
    bad["errored"] = True
    candidate = _write(tmp_path, "cand.json", [bad])
    verdict = compare(candidate, baseline, "errored")
    assert verdict.discordant == 0, "an errored item must not be scored as a miss"


def test_negatives_are_not_counted_in_a_recall_comparison(tmp_path: Path) -> None:
    """Recall is a statement about the positives; benign items belong to the FPR question."""
    baseline = _write(tmp_path, "base.json", [_sample("n", False, False, "safe")])
    candidate = _write(tmp_path, "cand.json", [_sample("n", False, True, "unsafe")])
    verdict = compare(candidate, baseline, "negatives")
    assert verdict.discordant == 0


def test_disjoint_corpora_refuse_rather_than_compare(tmp_path: Path) -> None:
    """Comparing two files with no shared ids is meaningless and must fail loudly.

    Silently returning zero discordant pairs would read as 'no difference', which is the most
    dangerous possible way to be wrong here.
    """
    baseline = _write(tmp_path, "base.json", [_sample("wg-1", True, True, "unsafe")])
    candidate = _write(tmp_path, "cand.json", [_sample("eg-1", True, True, "unsafe")])
    with pytest.raises(ValueError, match="share no sample ids"):
        compare(candidate, baseline, "mismatched")
