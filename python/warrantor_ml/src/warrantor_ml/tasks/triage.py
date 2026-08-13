"""Model 6: was the bound wrong, or was the agent wrong?

``/v1/summary/refusals`` already promises this sentence. What sits behind it is
``aggregate_refusals``, which compares two named constants -- ``REPEATED_OCCURRENCES = 5`` and
``SPREAD_WARRANTS = 2`` -- and emits ``RefusalSignal::BoundsProbablyWrong`` when both clear.
That is a threshold, and it is a defensible one, but it is not a classifier and the served
sentence reads as though it were.

The thing this module refuses to do
-----------------------------------
It refuses to train on ``RefusalSignal`` or ``RefusalGroup.guidance`` as labels. Distilling a
threshold produces a model that reproduces the threshold: it would learn to fire at five
occurrences across two warrants and would be, at its theoretical best, exactly as good as an
``if``. :func:`refuse_threshold_supervision` raises by name if anyone reaches for those fields.

Where the labels actually come from
-----------------------------------
From what the human did NEXT. A refusal against ``curl`` under warrant A is followed by grant B
for the same subject and repo; if B's bounds now contain ``curl``, the operator's own action
says the bound was wrong. If B was granted without it, the operator looked and decided the
agent was wrong. If no subsequent grant exists, the label is ``insufficient_evidence`` -- a real
label, not a gap to be filled by the majority class.

Where the output is allowed to go
---------------------------------
Nowhere near ``RefusalGroup.signal`` or ``RefusalGroup.guidance``. Those are the served verdict,
and a model judgement written into a field a human reads as the system's answer is precisely
what W1 forbids: a model's output is never a verdict. The model produces a separate
:class:`TriageEstimate` carrying ``source="model"``, a confidence, and the warrant ids it read.
Wiring it into ``/v1/summary/refusals`` -- as a clearly-attributed signal beside the threshold's
answer, never replacing it -- is a Rust change outside this workstream.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "FORBIDDEN_LABEL_SOURCES",
    "TRIAGE_LABELS",
    "ThresholdSupervisionRefused",
    "TriageEstimate",
    "TriageExample",
    "TriageFeatures",
    "build_triage_examples",
    "derive_label",
    "refuse_threshold_supervision",
    "triage_report",
]

TriageLabel = Literal["bound_was_wrong", "agent_was_wrong", "insufficient_evidence"]

#: The label vocabulary. ``insufficient_evidence`` is a first-class answer and the model is
#: trained to emit it, because the alternative is a model that always picks a side on a refusal
#: nobody ever followed up.
TRIAGE_LABELS: tuple[str, ...] = (
    "bound_was_wrong",
    "agent_was_wrong",
    "insufficient_evidence",
)

#: Fields of the served refusal summary that must never be used as training labels. Named so
#: the refusal message can name them.
FORBIDDEN_LABEL_SOURCES = ("signal", "guidance", "RefusalSignal", "RefusalGroup.guidance")


class ThresholdSupervisionRefused(ValueError):
    """Raised when the served threshold's own output was offered as a training label."""


def refuse_threshold_supervision(source_field: str) -> None:
    """Refuse a label drawn from the served threshold. Call this at every label seam.

    Raises:
        ThresholdSupervisionRefused: when ``source_field`` names the aggregation's own verdict.
    """

    if source_field in FORBIDDEN_LABEL_SOURCES:
        raise ThresholdSupervisionRefused(
            f"{source_field!r} is the output of `aggregate_refusals`, which is a comparison "
            "against REPEATED_OCCURRENCES=5 and SPREAD_WARRANTS=2. A model trained on it "
            "learns the threshold and cannot beat it -- its ceiling is an `if` statement. "
            "Derive labels from what the operator did NEXT: diff the following grant's bounds "
            "for the same subject against the bound that was refused"
        )


@dataclass(frozen=True)
class TriageFeatures:
    """What the model reads. Deliberately excludes the threshold's own verdict.

    ``occurrences`` and ``distinct_warrants`` are the raw counts the threshold is computed
    FROM, and those are legitimate inputs -- the model is allowed to see the evidence, it is
    just not allowed to be taught the answer the threshold derived from it.
    """

    kind: str
    subject: str
    occurrences: int
    distinct_warrants: int
    bounds_named: tuple[str, ...]
    goal: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise as the model's input record."""

        return {
            "kind": self.kind,
            "subject": self.subject,
            "occurrences": self.occurrences,
            "distinct_warrants": self.distinct_warrants,
            "bounds_named": list(self.bounds_named),
            "goal": self.goal,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class TriageExample:
    """One supervised example: features, the label, and how the label was derived."""

    example_id: str
    features: TriageFeatures
    label: TriageLabel
    label_provenance: str
    warrant_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Serialise one JSONL line."""

        return {
            "example_id": self.example_id,
            "features": self.features.to_dict(),
            "label": self.label,
            "label_provenance": self.label_provenance,
            "warrant_ids": list(self.warrant_ids),
        }


@dataclass(frozen=True)
class TriageEstimate:
    """The model's output. A separate record, never a served verdict.

    ``source`` is a constant ``"model"`` and is not a constructor parameter, so an estimate
    cannot be built that claims to be anything else. It carries the warrant ids it read so a
    human can check the reasoning against the same evidence, and it deliberately has no field
    that maps onto ``RefusalGroup.signal`` or ``RefusalGroup.guidance``.
    """

    subject: str
    label: TriageLabel
    confidence: float
    warrant_ids: tuple[str, ...]
    source: str = field(default="model", init=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the (future) API surface that would carry this beside the threshold."""

        return {
            "subject": self.subject,
            "estimate": self.label,
            "confidence": self.confidence,
            "warrant_ids": list(self.warrant_ids),
            "source": self.source,
            "note": "A model estimate, not a verdict. The served signal on a refusal group is "
            "computed by aggregate_refusals and is unaffected by this field.",
        }


def derive_label(
    refused_bound: str,
    refused_subject: str,
    subsequent_grant_bounds: Mapping[str, Sequence[str]] | None,
) -> tuple[TriageLabel, str]:
    """Label a refusal from the operator's next grant. Returns ``(label, provenance)``.

    Args:
        refused_bound: which bound refused it -- ``tools``, ``egress_hosts``, ``write_paths``.
        refused_subject: the tool name or destination that was refused.
        subsequent_grant_bounds: the next grant's bounds for the same subject and repo, or
            ``None`` when there was no subsequent grant.

    The reading is the operator's, not ours. Widening the exact bound that refused is an
    operator saying the bound was wrong. Granting again without widening it -- having seen the
    refusal in the summary -- is an operator saying the agent was wrong. No subsequent grant is
    no evidence, and it is labelled as such rather than assigned to whichever class is larger.
    """

    if subsequent_grant_bounds is None:
        return (
            "insufficient_evidence",
            "no subsequent grant for this subject; the operator never adjudicated it",
        )
    granted = {str(item) for item in subsequent_grant_bounds.get(refused_bound, ())}
    if refused_subject in granted:
        return (
            "bound_was_wrong",
            f"the next grant's {refused_bound} contains {refused_subject!r}; the operator "
            "widened the exact bound that refused",
        )
    return (
        "agent_was_wrong",
        f"the next grant re-granted without adding {refused_subject!r} to {refused_bound}; "
        "the operator saw the refusal and declined to widen",
    )


def build_triage_examples(
    refusal_groups: Sequence[Mapping[str, Any]],
    subsequent_grants: Mapping[str, Mapping[str, Sequence[str]]],
) -> tuple[TriageExample, ...]:
    """Build supervised examples from refusal groups plus the grants that followed.

    Args:
        refusal_groups: serialised ``RefusalGroup`` objects as ``/v1/summary/refusals`` returns
            them. The ``signal`` and ``guidance`` keys are present in that payload and are
            **read only to refuse them** -- see :func:`refuse_threshold_supervision`.
        subsequent_grants: ``subject -> bounds of the next grant``. Absent subject means no
            subsequent grant, which yields ``insufficient_evidence``.

    Raises:
        ThresholdSupervisionRefused: a group offered its own ``signal`` as the label -- that is,
            a caller passed a ``label`` key sourced from the aggregation.
    """

    examples: list[TriageExample] = []
    for index, group in enumerate(refusal_groups):
        if "label" in group and str(group["label"]) in {
            "bounds_probably_wrong",
            "repeated_in_one_run",
            "isolated",
        }:
            # Those three are `RefusalSignal`'s serde vocabulary. A `label` carrying one of them
            # is the threshold's verdict wearing a training label's name.
            refuse_threshold_supervision("signal")
        subject = str(group.get("subject", ""))
        bounds_named = tuple(str(item) for item in group.get("bounds", ()) or ())
        refused_bound = bounds_named[0] if bounds_named else "tools"
        label, provenance = derive_label(refused_bound, subject, subsequent_grants.get(subject))
        examples.append(
            TriageExample(
                example_id=f"triage-{index:05d}",
                features=TriageFeatures(
                    kind=str(group.get("kind", "")),
                    subject=subject,
                    occurrences=int(group.get("occurrences", 0)),
                    distinct_warrants=int(group.get("warrants", 0)),
                    bounds_named=bounds_named,
                    goal=str(group.get("goal", "")),
                    reason=str(group.get("reason", "")),
                ),
                label=label,
                label_provenance=provenance,
                warrant_ids=tuple(str(item) for item in group.get("warrant_ids", ()) or ()),
            )
        )
    return tuple(examples)


def triage_report(
    labels: Sequence[str],
    predictions: Sequence[str],
) -> dict[str, Any]:
    """Score model 6. The headline is the confident-wrong rate, not accuracy.

    Three-class accuracy would be an unusable summary here because the classes cost different
    amounts. Calling a wrong bound an agent problem leaves an operator fighting their own
    warrant; calling an agent problem a wrong bound argues for widening authority that should
    not be widened -- and that second error is the one that expands what an agent may do, so it
    is counted on its own.

    Predicting ``insufficient_evidence`` when the truth is decidable is an abstention: it costs
    a tuning signal, not authority, and is counted separately from being wrong.
    """

    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must be the same length")
    confusion: dict[str, dict[str, int]] = {
        actual: dict.fromkeys(TRIAGE_LABELS, 0) for actual in TRIAGE_LABELS
    }
    abstentions = 0
    widen_when_should_not = 0
    for actual, predicted in zip(labels, predictions, strict=True):
        if actual not in confusion or predicted not in TRIAGE_LABELS:
            raise ValueError(
                f"unknown triage label in ({actual!r}, {predicted!r}); vocabulary is "
                f"{list(TRIAGE_LABELS)}"
            )
        confusion[actual][predicted] += 1
        if predicted == "insufficient_evidence" and actual != "insufficient_evidence":
            abstentions += 1
        if actual == "agent_was_wrong" and predicted == "bound_was_wrong":
            widen_when_should_not += 1
    decidable = sum(1 for label in labels if label != "insufficient_evidence")
    return {
        "argues_to_widen_when_the_agent_was_wrong": widen_when_should_not,
        "argues_to_widen_rate": (widen_when_should_not / decidable) if decidable else 0.0,
        "abstentions_on_decidable_cases": abstentions,
        "decidable_cases": decidable,
        "confusion": confusion,
        "note": "The critical error is predicting bound_was_wrong when the agent was wrong: it "
        "argues for widening authority. An abstention costs a tuning signal only. Accuracy is "
        "not reported because the three errors do not cost the same.",
    }
