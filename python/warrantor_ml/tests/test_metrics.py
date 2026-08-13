"""Hand-checked confusion matrices and metric arithmetic.

Every expected value below was worked out by hand from the counts and written down before the
implementation was run, which is the only way a metrics test proves anything.
"""

from __future__ import annotations

import json

import pytest

from warrantor_ml.metrics import (
    ConfusionMatrix,
    confusion_matrix,
    per_category_recall,
    safe_divide,
    summarize,
    worst_categories,
)


def test_confusion_matrix_counts_each_quadrant() -> None:
    # unsafe=True is the positive class.
    labels = [True, True, True, True, False, False, False]
    predictions = [True, True, False, False, True, False, False]
    matrix = confusion_matrix(labels, predictions)
    assert matrix.true_positive == 2
    assert matrix.false_negative == 2
    assert matrix.false_positive == 1
    assert matrix.true_negative == 2
    assert matrix.total == 7
    assert matrix.actual_positive == 4
    assert matrix.actual_negative == 3


def test_hand_checked_rates() -> None:
    # TP=8, FN=2, FP=4, TN=6.
    matrix = ConfusionMatrix(true_positive=8, false_negative=2, false_positive=4, true_negative=6)
    assert matrix.recall == pytest.approx(8 / 10)  # 0.8
    assert matrix.miss_rate == pytest.approx(2 / 10)  # 0.2
    assert matrix.precision == pytest.approx(8 / 12)  # 0.6666...
    # F1 = 2 * (2/3) * (4/5) / ((2/3) + (4/5)) = (16/15) / (22/15) = 8/11
    assert matrix.f1 == pytest.approx(8 / 11)
    assert matrix.false_positive_rate == pytest.approx(4 / 10)  # 0.4
    assert matrix.accuracy == pytest.approx(14 / 20)  # 0.7
    assert matrix.recall + matrix.miss_rate == pytest.approx(1.0)


def test_perfect_and_useless_classifiers() -> None:
    perfect = ConfusionMatrix(true_positive=5, false_negative=0, false_positive=0, true_negative=5)
    assert perfect.recall == 1.0
    assert perfect.precision == 1.0
    assert perfect.f1 == 1.0
    assert perfect.miss_rate == 0.0

    # The failure mode the module exists to make visible: high accuracy, zero recall.
    misses_everything = ConfusionMatrix(
        true_positive=0, false_negative=5, false_positive=0, true_negative=95
    )
    assert misses_everything.recall == 0.0
    assert misses_everything.miss_rate == 1.0
    assert misses_everything.accuracy == pytest.approx(0.95)


def test_allow_everything_scores_perfect_precision_and_zero_recall() -> None:
    # ShieldGemma's shape: leading precision while missing most unsafe content.
    matrix = ConfusionMatrix(
        true_positive=1, false_negative=99, false_positive=0, true_negative=100
    )
    assert matrix.precision == 1.0
    assert matrix.recall == pytest.approx(0.01)


def test_safe_divide_returns_zero_not_nan() -> None:
    assert safe_divide(1.0, 0.0) == 0.0
    assert safe_divide(0.0, 0.0) == 0.0
    assert safe_divide(3.0, 4.0) == pytest.approx(0.75)


def test_empty_matrix_is_serialisable_json() -> None:
    empty = ConfusionMatrix(true_positive=0, false_negative=0, false_positive=0, true_negative=0)
    payload = json.dumps(summarize(empty).to_dict())
    assert "NaN" not in payload
    assert "Infinity" not in payload


def test_length_mismatch_is_rejected() -> None:
    with pytest.raises(ValueError, match="same length"):
        confusion_matrix([True, False], [True])


def test_summary_serialises_recall_first_and_accuracy_last() -> None:
    summary = summarize(
        ConfusionMatrix(true_positive=1, false_negative=1, false_positive=1, true_negative=1)
    )
    keys = list(summary.to_dict())
    assert keys[0] == "recall"
    assert keys.index("accuracy") > keys.index("precision")
    assert keys[-1] == "confusion_matrix"


def test_per_category_recall_only_counts_positives() -> None:
    labels = [True, True, True, False]
    predictions = [True, False, True, True]
    categories = [["violence"], ["violence", "jailbreak"], ["jailbreak"], ["violence"]]
    breakdown = per_category_recall(labels, predictions, categories)
    # violence appears on two UNSAFE samples (caught, missed) and one safe sample (ignored).
    assert breakdown["violence"] == {"recall": 0.5, "caught": 1, "total": 2}
    # jailbreak appears on two unsafe samples: one missed, one caught.
    assert breakdown["jailbreak"] == {"recall": 0.5, "caught": 1, "total": 2}


def test_per_category_recall_surfaces_a_wholly_missed_category() -> None:
    labels = [True] * 10
    predictions = [True] * 9 + [False]
    categories = [["violence"]] * 9 + [["jailbreak"]]
    breakdown = per_category_recall(labels, predictions, categories)
    assert breakdown["violence"]["recall"] == 1.0
    assert breakdown["jailbreak"]["recall"] == 0.0
    # Aggregate recall is 0.9 and hides the fact that a whole category is missed.
    assert confusion_matrix(labels, predictions).recall == pytest.approx(0.9)
    assert worst_categories(breakdown, limit=1) == ["jailbreak"]


def test_per_category_recall_rejects_ragged_input() -> None:
    with pytest.raises(ValueError, match="same length"):
        per_category_recall([True], [True], [])
