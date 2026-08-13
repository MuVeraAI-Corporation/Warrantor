"""The blind parity gate: two-sided, per-slice, and willing to say it could not tell."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from warrantor_ml.baselines import get_baseline
from warrantor_ml.leakage import LeakageReport, leakage_report
from warrantor_ml.parity import CandidateResult, load_candidate_result, parity_gate

_BASELINE_ID = "wildguardtest-qwen3guard-gen-4b"
_BASELINE = get_baseline(_BASELINE_ID)


def _clean_leakage() -> LeakageReport:
    return leakage_report([{"prompt": "training row"}], [{"prompt": "held out row"}])


def _slice(caught: int, positives: int, false_positives: int, negatives: int) -> dict[str, Any]:
    return {
        "recall": caught / positives if positives else 0.0,
        "confusion_matrix": {
            "true_positive": caught,
            "false_negative": positives - caught,
            "false_positive": false_positives,
            "true_negative": negatives - false_positives,
        },
    }


def _candidate(
    caught: int = 700,
    positives: int = 753,
    false_positives: int = 50,
    negatives: int = 946,
    lane: str = "local-rtx5080",
    precision: str = "gguf-q4_k_m",
    errors: int = 0,
    per_category: dict[str, float] | None = None,
) -> CandidateResult:
    return CandidateResult(
        candidate_id="guard-4b-weak-category",
        baseline_id=_BASELINE_ID,
        lane=lane,
        precision=precision,
        result_digest="sha256:" + "1" * 64,
        eval_set_digest="sha256:" + "2" * 64,
        manifest_digest="sha256:" + "3" * 64,
        slices={"overall": _slice(caught, positives, false_positives, negatives)},
        per_category_recall=per_category
        if per_category is not None
        else dict(_BASELINE.per_category_recall),
        backend_error_count=errors,
        scored_samples=positives + negatives,
    )


# ── the promotion rule ──────────────────────────────────────────────────────────────────


def test_a_genuine_improvement_with_a_steady_fpr_is_promoted() -> None:
    """Baseline 0.8554 recall / 0.0561 FPR; candidate 0.93 recall at the same FPR."""

    decision = parity_gate(_candidate(caught=700, false_positives=50), "overall", _clean_leakage())
    assert decision.verdict == "promote"
    assert decision.evidence["recall"]["verdict"] == "improved"


def test_recall_within_noise_is_a_reject_and_says_what_could_have_been_detected() -> None:
    baseline_slice = _BASELINE.slice("overall")
    decision = parity_gate(
        _candidate(caught=baseline_slice.caught + 3, false_positives=50),
        "overall",
        _clean_leakage(),
    )
    assert decision.verdict == "reject"
    assert any("within sampling noise" in reason for reason in decision.reasons)
    assert any("resolve about" in reason for reason in decision.reasons)


def test_a_recall_regression_is_named_as_a_regression_not_as_noise() -> None:
    decision = parity_gate(_candidate(caught=500, false_positives=50), "overall", _clean_leakage())
    assert decision.verdict == "reject"
    assert any("REGRESSED beyond sampling noise" in reason for reason in decision.reasons)


# ── the second side: an adapter that refuses everything ─────────────────────────────────


def test_recall_bought_with_false_positives_is_refused() -> None:
    """A one-sided gate promotes an adapter that flags all traffic. This one does not."""

    decision = parity_gate(_candidate(caught=750, false_positives=400), "overall", _clean_leakage())
    assert decision.verdict == "reject"
    assert any("false-positive rate REGRESSED" in reason for reason in decision.reasons)
    assert decision.evidence["recall"]["verdict"] == "improved"
    assert decision.evidence["false_positive_rate"]["regressed"] is True


def test_an_improved_false_positive_rate_does_not_block_promotion() -> None:
    decision = parity_gate(_candidate(caught=700, false_positives=10), "overall", _clean_leakage())
    assert decision.verdict == "promote"
    assert decision.evidence["false_positive_rate"]["regressed"] is False


# ── the third condition: a per-category floor ───────────────────────────────────────────


def test_a_category_falling_below_its_measured_floor_blocks_promotion() -> None:
    """An aggregate can improve while an entire class collapses. The aggregate hides it."""

    collapsed = dict(_BASELINE.per_category_recall)
    collapsed["fraud_assisting_illegal_activities"] = 0.20
    decision = parity_gate(
        _candidate(caught=700, false_positives=50, per_category=collapsed),
        "overall",
        _clean_leakage(),
    )
    assert decision.verdict == "reject"
    assert any("below a measured baseline floor" in reason for reason in decision.reasons)


def test_a_candidate_reporting_no_per_category_numbers_is_not_blocked_by_them() -> None:
    decision = parity_gate(
        _candidate(caught=700, false_positives=50, per_category={}), "overall", _clean_leakage()
    )
    assert decision.verdict == "promote"


# ── insufficient_evidence is a real answer ──────────────────────────────────────────────


def test_too_few_positives_yields_insufficient_evidence_not_a_verdict() -> None:
    """Promoting on forty samples is the over-conclusion the first baseline commit refused."""

    decision = parity_gate(
        _candidate(caught=38, positives=40, false_positives=2, negatives=60),
        "overall",
        _clean_leakage(),
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("below the floor" in reason for reason in decision.reasons)
    assert any("coin flip" in reason for reason in decision.reasons)


def test_a_leaking_eval_set_yields_insufficient_evidence() -> None:
    leaking = leakage_report([{"prompt": "a held out row"}], [{"prompt": "A held-out row!"}])
    decision = parity_gate(_candidate(caught=700), "overall", leaking)
    assert decision.verdict == "insufficient_evidence"
    assert any("not held out" in reason for reason in decision.reasons)


def test_a_run_with_too_many_backend_errors_yields_insufficient_evidence() -> None:
    """Fail-closed scores an error as HARMFUL, so errors buy recall."""

    decision = parity_gate(_candidate(caught=700, errors=200), "overall", _clean_leakage())
    assert decision.verdict == "insufficient_evidence"
    assert any("INFLATES recall" in reason for reason in decision.reasons)


def test_a_few_backend_errors_are_tolerated() -> None:
    decision = parity_gate(_candidate(caught=700, errors=5), "overall", _clean_leakage())
    assert decision.verdict == "promote"


def test_a_missing_slice_yields_insufficient_evidence_rather_than_a_crash() -> None:
    decision = parity_gate(_candidate(caught=700), "adversarial_true", _clean_leakage())
    assert decision.verdict == "insufficient_evidence"


# ── the cross-lane confound ─────────────────────────────────────────────────────────────


def test_a_kaggle_candidate_against_a_local_baseline_is_refused_not_scored() -> None:
    """fp16 loss scaling against a bf16-measured baseline is a confounded comparison."""

    decision = parity_gate(
        _candidate(caught=750, lane="kaggle-t4x2", precision="fp16"),
        "overall",
        _clean_leakage(),
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("confounded comparison" in reason for reason in decision.reasons)
    # And it never reports a delta for a comparison it refused.
    assert "recall" not in decision.evidence


def test_a_precision_mismatch_on_the_same_lane_is_also_refused() -> None:
    decision = parity_gate(_candidate(caught=750, precision="bf16"), "overall", _clean_leakage())
    assert decision.verdict == "insufficient_evidence"
    assert any("Re-measure the baseline" in reason for reason in decision.reasons)


# ── the decision record ─────────────────────────────────────────────────────────────────


def test_the_decision_carries_every_digest_needed_to_re_audit_it() -> None:
    decision = parity_gate(_candidate(caught=700), "overall", _clean_leakage())
    evidence = decision.evidence
    for key in (
        "baseline_digest",
        "candidate_result_digest",
        "eval_set_digest",
        "manifest_digest",
        "lane",
        "precision",
        "gate_slice",
    ):
        assert evidence[key], f"the decision record is missing {key}"


def test_the_decision_digest_is_stable() -> None:
    first = parity_gate(_candidate(caught=700), "overall", _clean_leakage())
    second = parity_gate(_candidate(caught=700), "overall", _clean_leakage())
    assert first.decision_digest == second.decision_digest
    assert first.decision_digest.startswith("sha256:")


def test_a_promotion_against_an_expguard_baseline_is_never_a_commercial_clearance() -> None:
    """The click-through is narrower than the licence and the corpus was frontier-generated."""

    expguard = get_baseline("expguardtest-qwen3guard-gen-4b").slice("overall")
    candidate = CandidateResult(
        candidate_id="guard-4b-weak-category",
        baseline_id="expguardtest-qwen3guard-gen-4b",
        lane="local-rtx5080",
        precision="gguf-q4_k_m",
        result_digest="sha256:" + "1" * 64,
        eval_set_digest="sha256:" + "2" * 64,
        manifest_digest="sha256:" + "3" * 64,
        slices={
            "overall": _slice(
                1150, expguard.positives, expguard.false_positives, expguard.negatives
            )
        },
        per_category_recall={},
        backend_error_count=0,
        scored_samples=2275,
    )
    decision = parity_gate(candidate, "overall", _clean_leakage())
    assert decision.verdict == "promote"
    assert "NOT CLEARED" in decision.evidence["commercial_clearance"]


# ── reading a real benchmark result document ────────────────────────────────────────────


def test_load_candidate_result_reads_the_benchmark_modules_own_document(tmp_path: Path) -> None:
    """The gate consumes what benchmark_wildguard writes; it never re-derives predictions."""

    document = {
        "result_digest": "sha256:" + "9" * 64,
        "eval_set": {"digest": "sha256:" + "8" * 64, "sample_count": 1699},
        "backend_errors": {"count": 2},
        "backend": {"kind": "ollama"},
        "wildguard_breakdowns": {
            "overall": _slice(700, 753, 50, 946),
            "adversarial_true": _slice(300, 341, 40, 455),
            "by_subcategory": {"others": {"recall": 0.81}},
            "severity_counts": {"safe": 900},
        },
    }
    path = tmp_path / "result.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    candidate = load_candidate_result(
        path,
        candidate_id="guard-4b-weak-category",
        baseline_id=_BASELINE_ID,
        lane="local-rtx5080",
        precision="gguf-q4_k_m",
        manifest_digest="sha256:" + "3" * 64,
    )
    assert set(candidate.slices) == {"overall", "adversarial_true"}
    assert candidate.slice_counts("overall") == (700, 753, 50, 946)
    assert candidate.per_category_recall == {"others": 0.81}
    assert candidate.backend_error_count == 2


def test_a_document_without_a_breakdown_block_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "not-a-result.json"
    path.write_text(json.dumps({"metrics": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="does not re-derive predictions"):
        load_candidate_result(
            path,
            candidate_id="x",
            baseline_id=_BASELINE_ID,
            lane="local-rtx5080",
            precision="gguf-q4_k_m",
            manifest_digest="",
        )
