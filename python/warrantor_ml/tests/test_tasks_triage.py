"""Model 6: labels come from what the operator did next, never from the threshold's own verdict."""

from __future__ import annotations

import pytest

from warrantor_ml.tasks.triage import (
    TRIAGE_LABELS,
    ThresholdSupervisionRefused,
    TriageEstimate,
    build_triage_examples,
    derive_label,
    refuse_threshold_supervision,
    triage_report,
)


def test_the_label_vocabulary_is_the_three() -> None:
    assert TRIAGE_LABELS == (
        "bound_was_wrong",
        "agent_was_wrong",
        "insufficient_evidence",
    )


# ── refusing to distil the threshold ────────────────────────────────────────────────────


@pytest.mark.parametrize("field", ["signal", "guidance", "RefusalSignal", "RefusalGroup.guidance"])
def test_the_served_thresholds_output_may_not_be_a_training_label(field: str) -> None:
    """aggregate_refusals compares against two constants; distilling it caps the model at an `if`."""

    with pytest.raises(ThresholdSupervisionRefused, match="REPEATED_OCCURRENCES=5"):
        refuse_threshold_supervision(field)


def test_a_legitimate_label_source_is_not_refused() -> None:
    refuse_threshold_supervision("next_grant_bounds")


def test_a_group_carrying_a_refusal_signal_as_its_label_is_refused() -> None:
    with pytest.raises(ThresholdSupervisionRefused):
        build_triage_examples(
            [{"subject": "curl", "label": "bounds_probably_wrong", "bounds": ["tools"]}],
            {},
        )


# ── labels from the operator's next action ──────────────────────────────────────────────


def test_widening_the_refused_bound_means_the_bound_was_wrong() -> None:
    label, provenance = derive_label("tools", "curl", {"tools": ["git", "curl"]})
    assert label == "bound_was_wrong"
    assert "widened the exact bound" in provenance


def test_regranting_without_widening_means_the_agent_was_wrong() -> None:
    label, provenance = derive_label("tools", "curl", {"tools": ["git"]})
    assert label == "agent_was_wrong"
    assert "declined to widen" in provenance


def test_no_subsequent_grant_is_insufficient_evidence_not_a_majority_class() -> None:
    label, provenance = derive_label("tools", "curl", None)
    assert label == "insufficient_evidence"
    assert "never adjudicated" in provenance


def test_widening_a_different_bound_does_not_count() -> None:
    """The operator has to widen the bound that actually refused."""

    label, _ = derive_label("tools", "curl", {"egress_hosts": ["curl"], "tools": ["git"]})
    assert label == "agent_was_wrong"


def test_build_triage_examples_derives_all_three_labels() -> None:
    groups = [
        {"kind": "tool", "subject": "curl", "occurrences": 7, "warrants": 3, "bounds": ["tools"]},
        {"kind": "tool", "subject": "rm", "occurrences": 2, "warrants": 1, "bounds": ["tools"]},
        {
            "kind": "egress",
            "subject": "evil.example",
            "occurrences": 1,
            "warrants": 1,
            "bounds": ["egress_hosts"],
        },
    ]
    examples = build_triage_examples(
        groups,
        {"curl": {"tools": ["git", "curl"]}, "rm": {"tools": ["git"]}},
    )
    assert [example.label for example in examples] == [
        "bound_was_wrong",
        "agent_was_wrong",
        "insufficient_evidence",
    ]


def test_the_features_carry_the_evidence_but_not_the_verdict() -> None:
    """The model may see the counts the threshold is computed from; not its answer."""

    examples = build_triage_examples(
        [
            {
                "kind": "tool",
                "subject": "curl",
                "occurrences": 7,
                "warrants": 3,
                "bounds": ["tools"],
                "signal": "bounds_probably_wrong",
                "guidance": "widen it deliberately",
            }
        ],
        {"curl": {"tools": ["curl"]}},
    )
    payload = examples[0].features.to_dict()
    assert payload["occurrences"] == 7
    assert payload["distinct_warrants"] == 3
    assert "signal" not in payload
    assert "guidance" not in payload


# ── the output is never a served verdict ────────────────────────────────────────────────


def test_a_triage_estimate_always_declares_itself_a_model_output() -> None:
    estimate = TriageEstimate(
        subject="curl", label="bound_was_wrong", confidence=0.8, warrant_ids=("w1",)
    )
    assert estimate.source == "model"


def test_source_cannot_be_set_at_construction() -> None:
    """An estimate that could claim another source could be mistaken for the served verdict."""

    with pytest.raises(TypeError):
        TriageEstimate(  # type: ignore[call-arg]
            subject="curl",
            label="bound_was_wrong",
            confidence=0.8,
            warrant_ids=(),
            source="system",
        )


def test_the_estimate_has_no_field_that_maps_onto_the_served_verdict() -> None:
    payload = TriageEstimate("curl", "bound_was_wrong", 0.8, ("w1",)).to_dict()
    assert "signal" not in payload
    assert "guidance" not in payload
    assert payload["source"] == "model"
    assert "not a verdict" in payload["note"]


# ── the metric ──────────────────────────────────────────────────────────────────────────


def test_the_critical_error_is_arguing_to_widen_when_the_agent_was_wrong() -> None:
    report = triage_report(
        ["agent_was_wrong", "agent_was_wrong", "bound_was_wrong"],
        ["bound_was_wrong", "agent_was_wrong", "bound_was_wrong"],
    )
    assert report["argues_to_widen_when_the_agent_was_wrong"] == 1
    assert report["decidable_cases"] == 3


def test_an_abstention_is_counted_separately_from_being_wrong() -> None:
    report = triage_report(["bound_was_wrong"], ["insufficient_evidence"])
    assert report["abstentions_on_decidable_cases"] == 1
    assert report["argues_to_widen_when_the_agent_was_wrong"] == 0


def test_accuracy_is_not_reported() -> None:
    """The three errors do not cost the same, so one number cannot summarise them."""

    report = triage_report(["bound_was_wrong"], ["bound_was_wrong"])
    assert "accuracy" not in report


def test_an_unknown_label_is_refused() -> None:
    with pytest.raises(ValueError, match="unknown triage label"):
        triage_report(["bound_was_wrong"], ["maybe"])


def test_mismatched_lengths_are_refused() -> None:
    with pytest.raises(ValueError, match="same length"):
        triage_report(["bound_was_wrong"], [])
