"""Model 7: infer a ``SideEffectClass`` for a proposed action.

The labels already exist in the schema, so this task is supervised by construction and the
interesting work is entirely in the cost model. The five classes and the consequential set are
mirrored from ``authority_spec::SideEffectClass``:

    Read | Write | Financial | Destructive | Physical

``is_consequential()`` is ``Financial | Destructive | Physical`` -- the three that invariant
I-08 requires a human approval for. So the errors are not interchangeable:

* Confusing ``Financial`` with ``Destructive`` is wrong and both still require approval. The
  action is still staged, a human still sees it. It costs precision in a report.
* Predicting ``Read`` for a ``Financial`` effect crosses the consequential boundary. The action
  stops requiring approval. Nobody sees it.

The headline metric is therefore **recall on the consequential set**, and downgrades across the
boundary are counted separately as critical errors. This is the same argument
:mod:`warrantor_ml.metrics` makes about a deny gate, applied to a five-way classifier: one
direction of error is discovered by the people running the system and the other is not.

Why an unknown class is an abstention and never ``Read``
--------------------------------------------------------
``SideEffectClass::parse`` returns ``Err(InvalidSideEffectClass)`` in Rust; it does not fall
back. A permissive default here would be worse than a parse error, because the least
consequential class is exactly the value that removes an effect from ``staged_classes``. And
``WarrantBounds::contains`` treats a smaller ``staged_classes`` set as an **expansion of
authority** -- so silently defaulting an unrecognised class to ``Read`` would narrow staging,
which the substrate classifies as granting authority, not restricting it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

__all__ = [
    "ABSTAIN",
    "CONSEQUENTIAL_CLASSES",
    "SIDE_EFFECT_CLASSES",
    "InvalidSideEffectClass",
    "effect_risk_report",
    "is_consequential",
    "parse_side_effect_class",
]

#: Mirrors ``authority_spec::SideEffectClass``'s five variants and their wire spellings.
SIDE_EFFECT_CLASSES: tuple[str, ...] = ("read", "write", "financial", "destructive", "physical")

#: Mirrors ``SideEffectClass::is_consequential`` -- the classes invariant I-08 requires a human
#: approval for.
CONSEQUENTIAL_CLASSES = frozenset({"financial", "destructive", "physical"})

#: What the model emits when it cannot decide. NOT a member of the class vocabulary, so it can
#: never be written into ``staged_classes`` by accident.
ABSTAIN = "abstain"


class InvalidSideEffectClass(ValueError):
    """Raised for a class string outside the five. Mirrors ``AaeError::InvalidSideEffectClass``."""


def parse_side_effect_class(value: str) -> str:
    """Parse a wire class string. Raises rather than defaulting -- see the module docstring.

    Raises:
        InvalidSideEffectClass: for anything outside the five variants.
    """

    normalised = value.strip().lower()
    if normalised not in SIDE_EFFECT_CLASSES:
        raise InvalidSideEffectClass(
            f"invalid side-effect class: {value!r}; the five are "
            f"{list(SIDE_EFFECT_CLASSES)}. There is deliberately no fallback: defaulting an "
            "unknown class to 'read' would drop it out of staged_classes, and a SMALLER "
            "staged_classes set is an expansion of authority in WarrantBounds::contains"
        )
    return normalised


def is_consequential(side_effect_class: str) -> bool:
    """Whether a class requires a human approval. Mirrors ``is_consequential()``."""

    return parse_side_effect_class(side_effect_class) in CONSEQUENTIAL_CLASSES


def _coerce_prediction(value: str) -> str:
    """A prediction is a class or an abstention. Anything else becomes an abstention.

    An unparseable model output is treated as "the model did not decide", which routes the
    action to a human, rather than as an error that gets dropped from the denominator. Dropping
    it would inflate every rate in the report by exactly the cases the model handled worst.
    """

    normalised = value.strip().lower()
    if normalised in SIDE_EFFECT_CLASSES:
        return normalised
    return ABSTAIN


def effect_risk_report(
    labels: Sequence[str],
    predictions: Sequence[str],
) -> dict[str, Any]:
    """Score model 7, consequential recall first and downgrades counted separately.

    Args:
        labels: ground-truth classes. Every one must parse -- a corrupt label is a corpus bug,
            not a model result, and it raises here rather than being scored.
        predictions: model outputs. Anything unrecognised is recorded as an abstention.

    The report leads with ``consequential_recall``: of the effects that genuinely required a
    human approval, how many did the model route to one. An abstention COUNTS as routing to a
    human, because that is what an abstention does -- it is the safe answer, not the right one,
    and ``abstentions`` is reported beside it so a model that abstains on everything is visible
    rather than flattered.
    """

    if len(labels) != len(predictions):
        raise ValueError(
            f"labels and predictions must be the same length, got {len(labels)} and "
            f"{len(predictions)}"
        )

    parsed_labels = [parse_side_effect_class(label) for label in labels]
    parsed_predictions = [_coerce_prediction(prediction) for prediction in predictions]

    consequential_total = 0
    consequential_routed = 0
    critical_downgrades: list[dict[str, str]] = []
    within_consequential_confusions = 0
    upgrades = 0
    abstentions = 0
    confusion: dict[str, dict[str, int]] = {
        actual: dict.fromkeys((*SIDE_EFFECT_CLASSES, ABSTAIN), 0) for actual in SIDE_EFFECT_CLASSES
    }

    for index, (actual, predicted) in enumerate(
        zip(parsed_labels, parsed_predictions, strict=True)
    ):
        confusion[actual][predicted] += 1
        if predicted == ABSTAIN:
            abstentions += 1
        actual_consequential = actual in CONSEQUENTIAL_CLASSES
        # An abstention routes to a human, which is what a consequential class needs. It is not
        # a correct classification and is counted as an abstention too.
        predicted_consequential = predicted in CONSEQUENTIAL_CLASSES or predicted == ABSTAIN
        if actual_consequential:
            consequential_total += 1
            if predicted_consequential:
                consequential_routed += 1
                if predicted != actual and predicted != ABSTAIN:
                    within_consequential_confusions += 1
            else:
                # THE critical error: an effect that needed an approval no longer requires one.
                critical_downgrades.append(
                    {"index": str(index), "actual": actual, "predicted": predicted}
                )
        elif predicted in CONSEQUENTIAL_CLASSES:
            upgrades += 1

    return {
        "consequential_recall": (
            consequential_routed / consequential_total if consequential_total else 0.0
        ),
        "consequential_positives": consequential_total,
        "critical_downgrade_count": len(critical_downgrades),
        "critical_downgrades": critical_downgrades[:20],
        "within_consequential_confusions": within_consequential_confusions,
        "upgrades_to_consequential": upgrades,
        "abstentions": abstentions,
        "confusion": confusion,
        "note": "Leading metric is recall on the consequential set (financial/destructive/"
        "physical), because a downgrade across that boundary removes the human approval "
        "invariant I-08 requires. A confusion WITHIN the consequential set still stages the "
        "effect and still shows a human; it is counted separately and it is not the same "
        "failure. An abstention routes to a human and is never a fall-back to 'read'.",
    }
