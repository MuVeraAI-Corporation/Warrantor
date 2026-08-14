"""The blind parity gate: two-sided, per-slice, and willing to say it could not tell."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from warrantor_ml.baselines import get_baseline
from warrantor_ml.leakage import LeakageReport, leakage_report
from warrantor_ml.parity import (
    CandidateResult,
    corpus_digest_of,
    load_candidate_result,
    parity_gate,
)

_BASELINE_ID = "wildguardtest-qwen3guard-gen-4b"
_BASELINE = get_baseline(_BASELINE_ID)
_EXPGUARD_ID = "expguardtest-qwen3guard-gen-4b"
_EXPGUARD = get_baseline(_EXPGUARD_ID)

#: What benchmark_wildguard / benchmark_expguard write as ``eval_set.source``.
_WILDGUARD_SOURCE = "allenai/wildguardmix:test/wildguard_test.parquet"
_EXPGUARD_SOURCE = "6rightjade/expguardmix:expguardtest.parquet"


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
    baseline_id: str = _BASELINE_ID,
    corpus_source: str = _WILDGUARD_SOURCE,
    eval_set_digest: str = "sha256:" + "2" * 64,
    slices: dict[str, dict[str, Any]] | None = None,
) -> CandidateResult:
    return CandidateResult(
        candidate_id="guard-4b-weak-category",
        baseline_id=baseline_id,
        lane=lane,
        precision=precision,
        result_digest="sha256:" + "1" * 64,
        eval_set_digest=eval_set_digest,
        eval_corpus_digest=corpus_digest_of(corpus_source),
        manifest_digest="sha256:" + "3" * 64,
        slices=slices
        if slices is not None
        else {"overall": _slice(caught, positives, false_positives, negatives)},
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


def test_a_candidate_reporting_no_per_category_numbers_cannot_be_promoted_by_them() -> None:
    """A floor that was not evaluated is not a floor that was cleared.

    This test used to assert ``promote`` -- it enshrined the vacuous pass, and the promotion
    reason went on to state that no per-category recall fell below its floor when no floor had
    been looked at. Promotion requires all three conditions; only two were testable here.
    """

    decision = parity_gate(
        _candidate(caught=700, false_positives=50, per_category={}), "overall", _clean_leakage()
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("could not be evaluated" in reason for reason in decision.reasons)
    assert decision.evidence["per_category_floors_not_evaluated"]
    assert decision.evidence["per_category_floors_checked"] == []


def test_a_floor_spelled_the_other_vocabularys_way_is_still_enforced() -> None:
    """baselines.py stores 'unqualified professional advice'; ExpGuard emits it in title case.

    The gate's lookup was an exact dict hit, so the floor protecting the ONE measured weak class
    (0.4298, the weakness the weak-category recipes exist to repair) never matched anything --
    ``observed`` was always None and the condition was skipped. ``tasks/guard._matches_category``
    already normalised case and underscores for exactly this reason.
    """

    collapsed = parity_gate(
        _candidate(
            caught=1150,
            positives=_EXPGUARD.slice("overall").positives,
            false_positives=20,
            negatives=_EXPGUARD.slice("overall").negatives,
            per_category={"Unqualified Professional Advice": 0.05},
            baseline_id=_EXPGUARD_ID,
            corpus_source=_EXPGUARD_SOURCE,
        ),
        "overall",
        _clean_leakage(),
    )
    assert collapsed.verdict == "reject"
    assert any("below the baseline floor 0.4298" in reason for reason in collapsed.reasons)

    # And the same spelling above the floor is recognised as a pass, not as an absence.
    cleared = parity_gate(
        _candidate(
            caught=1150,
            positives=_EXPGUARD.slice("overall").positives,
            false_positives=20,
            negatives=_EXPGUARD.slice("overall").negatives,
            per_category={"Unqualified Professional Advice": 0.80},
            baseline_id=_EXPGUARD_ID,
            corpus_source=_EXPGUARD_SOURCE,
        ),
        "overall",
        _clean_leakage(),
    )
    assert cleared.verdict == "promote"
    assert cleared.evidence["per_category_floors_checked"] == ["unqualified professional advice"]


def test_the_promotion_reason_only_claims_floors_it_actually_checked() -> None:
    """The record must not assert a check that did not run. It said so unconditionally before."""

    decision = parity_gate(_candidate(caught=700, false_positives=50), "overall", _clean_leakage())
    assert decision.verdict == "promote"
    assert "3 measured per-category floors" in decision.reasons[0]
    assert len(decision.evidence["per_category_floors_checked"]) == 3


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

    expguard = _EXPGUARD.slice("overall")
    decision = parity_gate(
        _candidate(
            caught=1150,
            positives=expguard.positives,
            false_positives=20,
            negatives=expguard.negatives,
            per_category={"unqualified professional advice": 0.80},
            baseline_id=_EXPGUARD_ID,
            corpus_source=_EXPGUARD_SOURCE,
        ),
        "overall",
        _clean_leakage(),
    )
    assert decision.verdict == "promote"
    assert "NOT CLEARED" in decision.evidence["commercial_clearance"]


# ── the two-sided gate never degrades to a one-sided one ────────────────────────────────


def test_a_slice_with_no_baseline_negatives_refuses_instead_of_going_one_sided() -> None:
    """The finding, reproduced: 900 false positives out of 1000 negatives used to PROMOTE.

    Every ExpGuard per-domain slice is recorded with ``negatives=0`` -- the published report
    breaks the false-positive rate down overall only, and baselines.py says in as many words that
    a per-domain FPR comparison "must return insufficient_evidence rather than a number".
    ``two_proportion_z`` returns None for a zero-trial arm, ``significant_improvement`` folds that
    to ``within_noise``, and ``fpr_verdict == 'improved'`` is then False -- so no reason was
    appended and the gate promoted on the recall test alone, printing the 0.90 false-positive
    rate in the promotion reason as evidence that it had not regressed.
    """

    healthcare = _EXPGUARD.slice("healthcare")
    assert healthcare.negatives == 0, "the fixture this test is written against has changed"

    decision = parity_gate(
        _candidate(
            caught=390,
            positives=healthcare.positives,
            false_positives=900,
            negatives=1000,
            per_category={"unqualified professional advice": 0.99},
            baseline_id=_EXPGUARD_ID,
            corpus_source=_EXPGUARD_SOURCE,
            slices={"healthcare": _slice(390, healthcare.positives, 900, 1000)},
        ),
        "healthcare",
        _clean_leakage(),
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("false-positive side of the gate cannot be computed" in r for r in decision.reasons)
    # And it must not report a delta for a comparison it refused to run.
    assert "false_positive_rate" not in decision.evidence
    assert "recall" not in decision.evidence


def test_a_candidate_with_no_negatives_of_its_own_is_also_refused() -> None:
    """Symmetry: an empty arm on either side makes the false-positive test uncomputable."""

    decision = parity_gate(
        _candidate(caught=700, false_positives=0, negatives=0), "overall", _clean_leakage()
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("candidate arm 0" in reason for reason in decision.reasons)


# ── a candidate is bound to the corpus its baseline was measured on ─────────────────────


def test_an_expguard_result_scored_against_the_wildguard_baseline_is_refused() -> None:
    """The exact confusion the CLI permits: every guard recipe declares the WildGuard baseline.

    ``--breakdown-key expguard_breakdowns`` reads an ExpGuardTest document; ``_lane_matches``
    checks only lane and precision; ``eval_set_digest`` was recorded and never compared. The
    result was a promotion record, digested and archived as auditable evidence, comparing two
    different corpora and naming the wrong baseline on its own face.
    """

    decision = parity_gate(
        _candidate(caught=700, false_positives=50, corpus_source=_EXPGUARD_SOURCE),
        "overall",
        _clean_leakage(),
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("scored on a different corpus" in reason for reason in decision.reasons)
    assert (
        decision.evidence["baseline_corpus"] == "allenai/wildguardmix:test/wildguard_test.parquet"
    )
    assert "recall" not in decision.evidence


def test_a_result_document_that_does_not_name_its_corpus_is_refused() -> None:
    """An unnamed corpus is refused, never assumed to be the right one."""

    decision = parity_gate(
        _candidate(caught=700, false_positives=50, corpus_source=""), "overall", _clean_leakage()
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("does not name the corpus" in reason for reason in decision.reasons)


def test_the_corpus_binding_matches_what_the_benchmark_modules_actually_write() -> None:
    """A binding computed from a string the producers do not emit would refuse everything."""

    from warrantor_ml.benchmark_expguard import EXPGUARD_TEST_FILE, EXPGUARD_TEST_REPO
    from warrantor_ml.benchmark_wildguard import WILDGUARD_TEST_FILE, WILDGUARD_TEST_REPO

    assert (
        corpus_digest_of(f"{WILDGUARD_TEST_REPO}:{WILDGUARD_TEST_FILE}") == _BASELINE.corpus_digest
    )
    assert corpus_digest_of(f"{EXPGUARD_TEST_REPO}:{EXPGUARD_TEST_FILE}") == _EXPGUARD.corpus_digest
    assert _BASELINE.corpus_digest != _EXPGUARD.corpus_digest


# ── a decision must be re-auditable against the evidence behind it ──────────────────────


def test_a_result_document_with_no_eval_set_digest_is_refused() -> None:
    """The decision digest is sold as pinning a promotion to its evidence; the evidence is the set."""

    decision = parity_gate(
        _candidate(caught=700, false_positives=50, eval_set_digest=""), "overall", _clean_leakage()
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("no `eval_set.digest`" in reason for reason in decision.reasons)


# ── no measured baseline is not a rejection ─────────────────────────────────────────────


def test_a_recipe_with_no_measured_baseline_yields_insufficient_evidence_not_a_crash() -> None:
    """The four substrate recipes declare baseline_id ''. get_baseline('') used to raise.

    An unhandled KeyError exits 1, which the CLI's own docstring assigns to ``reject`` -- the
    status it deliberately separates from ``insufficient_evidence`` (3) so a CI job does not
    retry the wrong one. RFC W2's M3 milestone says the gate "will correctly return
    insufficient_evidence" for models 5-7; it could not.
    """

    decision = parity_gate(_candidate(caught=700, baseline_id=""), "overall", _clean_leakage())
    assert decision.verdict == "insufficient_evidence"
    assert any("no measured baseline" in reason for reason in decision.reasons)


def test_an_unknown_baseline_id_is_a_refusal_rather_than_an_exception() -> None:
    decision = parity_gate(
        _candidate(caught=700, baseline_id="not-a-baseline"), "overall", _clean_leakage()
    )
    assert decision.verdict == "insufficient_evidence"
    assert any("unknown baseline" in reason for reason in decision.reasons)


def test_a_slice_the_baseline_does_not_carry_is_a_refusal_rather_than_an_exception() -> None:
    """`baseline.slice()` sat outside the try that guarded the candidate's slice lookup."""

    missing = parity_gate(
        _candidate(
            caught=700,
            baseline_id=_EXPGUARD_ID,
            corpus_source=_EXPGUARD_SOURCE,
            slices={"adversarial_true": _slice(300, 341, 40, 455)},
        ),
        "adversarial_true",
        _clean_leakage(),
    )
    assert missing.verdict == "insufficient_evidence"
    assert any("no slice 'adversarial_true'" in reason for reason in missing.reasons)


# ── reading a real benchmark result document ────────────────────────────────────────────


def test_load_candidate_result_reads_the_benchmark_modules_own_document(tmp_path: Path) -> None:
    """The gate consumes what benchmark_wildguard writes; it never re-derives predictions.

    The ``eval_set`` block here is the one ``benchmark_wildguard.build_eval_set_descriptor``
    actually produces, not a hand-invented shape. The previous version of this test fed a
    synthetic document carrying an ``eval_set.digest`` field the real producers never emitted,
    which is how a test named for fidelity to the producers passed while the production path
    recorded ``eval_set_digest: ""`` in every decision.
    """

    from warrantor_ml.benchmark_wildguard import build_eval_set_descriptor

    parquet = tmp_path / "wildguard_test.parquet"
    parquet.write_bytes(b"not really a parquet, but it has bytes and therefore a digest")
    descriptor = build_eval_set_descriptor(parquet, range(1725), range(1699), ["r1", "r2"])
    descriptor["sample_count"] = 1699

    document = {
        "result_digest": "sha256:" + "9" * 64,
        "eval_set": descriptor,
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
    # The two bindings the decision record rests on, read off a real producer's descriptor.
    assert candidate.eval_set_digest.startswith("sha256:")
    assert candidate.eval_corpus_digest == _BASELINE.corpus_digest


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
