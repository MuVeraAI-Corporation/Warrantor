"""Model 7: the five classes mirrored from Rust, and the boundary that must not be crossed."""

from __future__ import annotations

import pytest

from warrantor_ml.tasks.effects import (
    ABSTAIN,
    CONSEQUENTIAL_CLASSES,
    SIDE_EFFECT_CLASSES,
    InvalidSideEffectClass,
    effect_risk_report,
    is_consequential,
    parse_side_effect_class,
)


def test_the_five_variants_mirror_the_rust_enum() -> None:
    assert SIDE_EFFECT_CLASSES == ("read", "write", "financial", "destructive", "physical")


def test_is_consequential_mirrors_the_rust_predicate() -> None:
    """Financial | Destructive | Physical -- the classes invariant I-08 needs an approval for."""

    assert frozenset({"financial", "destructive", "physical"}) == CONSEQUENTIAL_CLASSES
    assert is_consequential("financial") is True
    assert is_consequential("destructive") is True
    assert is_consequential("physical") is True
    assert is_consequential("read") is False
    assert is_consequential("write") is False


def test_an_unknown_class_raises_rather_than_defaulting() -> None:
    """SideEffectClass::parse returns Err in Rust. A permissive default would narrow staging,
    and a smaller staged_classes set is an EXPANSION of authority in WarrantBounds::contains."""

    with pytest.raises(InvalidSideEffectClass, match="expansion of authority"):
        parse_side_effect_class("mostly harmless")


def test_parsing_normalises_case_and_whitespace() -> None:
    assert parse_side_effect_class("  Financial ") == "financial"


def test_abstain_is_not_a_member_of_the_class_vocabulary() -> None:
    """So it can never be written into staged_classes by accident."""

    assert ABSTAIN not in SIDE_EFFECT_CLASSES
    with pytest.raises(InvalidSideEffectClass):
        parse_side_effect_class(ABSTAIN)


# ── the cost model ──────────────────────────────────────────────────────────────────────


def test_a_downgrade_across_the_consequential_boundary_is_the_critical_error() -> None:
    report = effect_risk_report(["financial"], ["read"])
    assert report["critical_downgrade_count"] == 1
    assert report["consequential_recall"] == 0.0
    assert report["critical_downgrades"][0]["actual"] == "financial"


def test_a_confusion_within_the_consequential_set_is_not_a_critical_error() -> None:
    """Both still stage the effect and both still show a human. It costs precision, not safety."""

    report = effect_risk_report(["financial"], ["destructive"])
    assert report["critical_downgrade_count"] == 0
    assert report["within_consequential_confusions"] == 1
    assert report["consequential_recall"] == 1.0


def test_an_abstention_routes_to_a_human_and_counts_as_routed() -> None:
    report = effect_risk_report(["financial"], [ABSTAIN])
    assert report["consequential_recall"] == 1.0
    assert report["critical_downgrade_count"] == 0
    assert report["abstentions"] == 1


def test_an_unparseable_prediction_becomes_an_abstention_not_a_dropped_row() -> None:
    """Dropping it would inflate every rate by exactly the cases the model handled worst."""

    report = effect_risk_report(["financial", "read"], ["complete gibberish", "read"])
    assert report["abstentions"] == 1
    assert report["consequential_positives"] == 1
    assert report["consequential_recall"] == 1.0


def test_an_unparseable_prediction_never_becomes_read() -> None:
    report = effect_risk_report(["read"], ["gibberish"])
    assert report["confusion"]["read"][ABSTAIN] == 1
    assert report["confusion"]["read"]["read"] == 0


def test_upgrading_a_benign_effect_is_counted_but_is_not_critical() -> None:
    report = effect_risk_report(["read"], ["financial"])
    assert report["upgrades_to_consequential"] == 1
    assert report["critical_downgrade_count"] == 0


def test_the_headline_is_consequential_recall() -> None:
    labels = ["financial", "destructive", "physical", "read", "write"]
    predictions = ["financial", "destructive", "read", "read", "write"]
    report = effect_risk_report(labels, predictions)
    assert report["consequential_positives"] == 3
    assert report["consequential_recall"] == pytest.approx(2 / 3)
    assert report["critical_downgrade_count"] == 1


def test_a_corrupt_ground_truth_label_raises_rather_than_being_scored() -> None:
    """A corrupt label is a corpus bug, not a model result."""

    with pytest.raises(InvalidSideEffectClass):
        effect_risk_report(["not-a-class"], ["read"])


def test_mismatched_lengths_are_refused() -> None:
    with pytest.raises(ValueError, match="same length"):
        effect_risk_report(["read"], [])


def test_the_note_names_the_boundary_rather_than_the_accuracy() -> None:
    report = effect_risk_report(["read"], ["read"])
    assert "accuracy" not in report
    assert "consequential" in report["note"]
