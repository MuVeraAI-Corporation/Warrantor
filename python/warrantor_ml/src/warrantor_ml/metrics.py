"""Classification metrics for a deny gate, with recall first.

Recall leads every structure in this module, and that ordering is deliberate rather than
decorative. For a content-moderation deny gate the two error types are not symmetric:

* A **false negative** -- unsafe content the guard called safe -- is emitted to the user and
  recorded in the logs as a successful, unremarkable request. Nobody files a ticket. It is
  invisible until it is a headline.
* A **false positive** -- safe content the guard called unsafe -- surfaces immediately in the
  refusal list, gets complained about, and gets tuned away.

So recall is the metric under which the gate actually fails, and aggregate accuracy is the
metric that hides it. The ICLR 2026 workshop benchmark (arXiv:2605.28830, 14 guard models,
79,331 samples) makes the point concretely: ShieldGemma has the highest precision at 82.20%
while missing 54.51% of unsafe content, and GPT-OSS Safeguard 20B misses 75.14%. Neither of
those is visible in an accuracy headline.

Positive class = "unsafe". A true positive is unsafe content correctly flagged.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ConfusionMatrix",
    "MetricSummary",
    "confusion_matrix",
    "per_category_recall",
    "safe_divide",
    "summarize",
]


def safe_divide(numerator: float, denominator: float) -> float:
    """Divide, returning 0.0 when the denominator is zero.

    An undefined ratio is reported as 0.0 rather than raising or emitting NaN, because these
    values are serialised into a signed evaluation record and NaN is not valid JSON. Callers
    that need to distinguish "0.0 because the model got everything wrong" from "0.0 because
    there were no positives" must read the confusion-matrix counts, which are always emitted
    alongside.
    """

    if denominator == 0:
        return 0.0
    return numerator / denominator


@dataclass(frozen=True)
class ConfusionMatrix:
    """Counts for a binary safe/unsafe decision. Positive class is "unsafe"."""

    true_positive: int
    false_negative: int
    false_positive: int
    true_negative: int

    @property
    def total(self) -> int:
        """Total number of scored samples."""

        return self.true_positive + self.false_negative + self.false_positive + self.true_negative

    @property
    def actual_positive(self) -> int:
        """How many samples were genuinely unsafe."""

        return self.true_positive + self.false_negative

    @property
    def actual_negative(self) -> int:
        """How many samples were genuinely safe."""

        return self.false_positive + self.true_negative

    @property
    def recall(self) -> float:
        """TP / (TP + FN) -- the fraction of unsafe content the gate actually caught."""

        return safe_divide(self.true_positive, self.actual_positive)

    @property
    def miss_rate(self) -> float:
        """FN / (TP + FN) -- the fraction of unsafe content that got through. 1 - recall."""

        return safe_divide(self.false_negative, self.actual_positive)

    @property
    def precision(self) -> float:
        """TP / (TP + FP) -- of everything flagged, how much was genuinely unsafe."""

        return safe_divide(self.true_positive, self.true_positive + self.false_positive)

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""

        denominator = self.precision + self.recall
        return safe_divide(2 * self.precision * self.recall, denominator)

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) -- how much safe content the gate refuses."""

        return safe_divide(self.false_positive, self.actual_negative)

    @property
    def accuracy(self) -> float:
        """(TP + TN) / total. Reported last, on purpose. Never lead with this number."""

        return safe_divide(self.true_positive + self.true_negative, self.total)

    def to_dict(self) -> dict[str, int]:
        """Serialise the raw counts."""

        return {
            "true_positive": self.true_positive,
            "false_negative": self.false_negative,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "total": self.total,
        }


def confusion_matrix(
    labels: Sequence[bool],
    predictions: Sequence[bool],
) -> ConfusionMatrix:
    """Build a confusion matrix from aligned ground-truth and predicted "is unsafe" flags."""

    if len(labels) != len(predictions):
        raise ValueError(
            f"labels and predictions must be the same length, got {len(labels)} and "
            f"{len(predictions)}"
        )
    true_positive = false_negative = false_positive = true_negative = 0
    for label, prediction in zip(labels, predictions, strict=True):
        if label and prediction:
            true_positive += 1
        elif label and not prediction:
            false_negative += 1
        elif not label and prediction:
            false_positive += 1
        else:
            true_negative += 1
    return ConfusionMatrix(
        true_positive=true_positive,
        false_negative=false_negative,
        false_positive=false_positive,
        true_negative=true_negative,
    )


@dataclass(frozen=True)
class MetricSummary:
    """The headline metrics, ordered so recall is read first."""

    recall: float
    miss_rate: float
    precision: float
    f1: float
    false_positive_rate: float
    accuracy: float
    matrix: ConfusionMatrix

    def to_dict(self) -> dict[str, Any]:
        """Serialise with recall first. Dict insertion order is preserved by ``json.dumps``."""

        return {
            "recall": self.recall,
            "miss_rate": self.miss_rate,
            "precision": self.precision,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "accuracy": self.accuracy,
            "confusion_matrix": self.matrix.to_dict(),
        }


def summarize(matrix: ConfusionMatrix) -> MetricSummary:
    """Derive the headline metrics from a confusion matrix."""

    return MetricSummary(
        recall=matrix.recall,
        miss_rate=matrix.miss_rate,
        precision=matrix.precision,
        f1=matrix.f1,
        false_positive_rate=matrix.false_positive_rate,
        accuracy=matrix.accuracy,
        matrix=matrix,
    )


def per_category_recall(
    labels: Sequence[bool],
    predictions: Sequence[bool],
    categories: Sequence[Iterable[str]],
) -> dict[str, dict[str, float | int]]:
    """Recall broken down by ground-truth harm category.

    A model can post a strong aggregate recall while missing an entire category, and an
    aggregate number will never show it. Only unsafe samples contribute: recall is undefined
    for a category with no positives.
    """

    if not (len(labels) == len(predictions) == len(categories)):
        raise ValueError("labels, predictions and categories must all be the same length")
    caught: Counter[str] = Counter()
    seen: Counter[str] = Counter()
    for label, prediction, category_set in zip(labels, predictions, categories, strict=True):
        if not label:
            continue
        for category in category_set:
            seen[category] += 1
            if prediction:
                caught[category] += 1
    return {
        category: {
            "recall": safe_divide(caught[category], seen[category]),
            "caught": caught[category],
            "total": seen[category],
        }
        for category in sorted(seen)
    }


def worst_categories(
    breakdown: Mapping[str, Mapping[str, float | int]],
    limit: int = 3,
) -> list[str]:
    """The categories with the lowest recall, worst first. Ties break alphabetically."""

    ranked = sorted(breakdown.items(), key=lambda item: (float(item[1]["recall"]), item[0]))
    return [name for name, _ in ranked[:limit]]
