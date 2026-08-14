"""The frozen baselines, checked for internal consistency against ml/README.md.

The counts here are solved from the published rates. If a transcription slips, these tests fail
rather than the significance threshold silently moving -- which is the whole reason the counts
are literals instead of being recomputed at read time.
"""

from __future__ import annotations

import pytest

from warrantor_ml.baselines import BASELINES, get_baseline


def test_every_measured_baseline_is_registered() -> None:
    assert set(BASELINES) == {
        "wildguardtest-qwen3guard-gen-4b",
        "expguardtest-qwen3guard-gen-4b",
        "wildguardtest-qwen3guard-gen-0.6b",
    }


def test_the_same_size_comparator_exists_for_the_0_6b_recipes() -> None:
    """Without it a rejection cannot separate "the fine-tune failed" from "0.6B < 4B".

    The four guard-0.6b-* recipes declare the 4B baseline, so a candidate is asked to beat a
    model seven times its size. That is a legitimate product question -- can we ship the small
    one -- but it is not the question "did tuning help", and only a same-size baseline answers
    that one.
    """

    small = get_baseline("wildguardtest-qwen3guard-gen-0.6b")
    large = get_baseline("wildguardtest-qwen3guard-gen-4b")

    # Same corpus and split, or the comparison is refused by the gate's corpus binding.
    assert (small.corpus, small.split) == (large.corpus, large.split)
    assert small.backend["precision"] == large.backend["precision"]

    # The finding the baseline exists to record: the gap is smaller than the split can resolve.
    small_recall = next(s for s in small.slices if s.name == "overall").recall
    large_recall = next(s for s in large.slices if s.name == "overall").recall
    assert abs(large_recall - small_recall) < 0.01


def test_an_unknown_baseline_names_the_ones_that_exist() -> None:
    with pytest.raises(KeyError, match="measured:"):
        get_baseline("something-else")


# ── the published WildGuardTest figures ─────────────────────────────────────────────────


def test_wildguard_headline_numbers_match_the_readme() -> None:
    baseline = get_baseline("wildguardtest-qwen3guard-gen-4b")
    overall = baseline.slice("overall")
    assert overall.recall == 0.8554
    assert overall.precision == 0.9241
    assert overall.false_positive_rate == 0.0561
    assert overall.total == 1699


def test_the_adversarial_gap_is_the_measured_one() -> None:
    """Recall falls 7.3 points and the false-positive rate quadruples."""

    baseline = get_baseline("wildguardtest-qwen3guard-gen-4b")
    plain = baseline.slice("adversarial_false")
    adversarial = baseline.slice("adversarial_true")
    assert round(plain.recall - adversarial.recall, 4) == 0.0734
    assert adversarial.false_positive_rate / plain.false_positive_rate > 4.0


def test_the_adversarial_arms_sum_to_the_overall_arm() -> None:
    """The solved counts have to be mutually consistent or the significance test is wrong."""

    baseline = get_baseline("wildguardtest-qwen3guard-gen-4b")
    overall = baseline.slice("overall")
    plain = baseline.slice("adversarial_false")
    adversarial = baseline.slice("adversarial_true")
    assert plain.positives + adversarial.positives == overall.positives
    assert plain.negatives + adversarial.negatives == overall.negatives
    assert plain.total is not None and adversarial.total is not None
    assert plain.total + adversarial.total == overall.total


@pytest.mark.parametrize(
    "baseline_id,slice_name",
    [
        ("wildguardtest-qwen3guard-gen-4b", "overall"),
        ("wildguardtest-qwen3guard-gen-4b", "adversarial_false"),
        ("wildguardtest-qwen3guard-gen-4b", "adversarial_true"),
        ("expguardtest-qwen3guard-gen-4b", "overall"),
    ],
)
def test_the_solved_counts_reproduce_the_published_precision(
    baseline_id: str, slice_name: str
) -> None:
    """Precision is the fourth equation the positive/negative split was solved from."""

    measured = get_baseline(baseline_id).slice(slice_name)
    assert measured.precision is not None
    implied = measured.caught / (measured.caught + measured.false_positives)
    assert implied == pytest.approx(measured.precision, abs=0.002)


@pytest.mark.parametrize(
    "baseline_id,slice_name",
    [
        ("wildguardtest-qwen3guard-gen-4b", "overall"),
        ("wildguardtest-qwen3guard-gen-4b", "adversarial_true"),
        ("expguardtest-qwen3guard-gen-4b", "overall"),
    ],
)
def test_positives_plus_negatives_equal_the_published_row_count(
    baseline_id: str, slice_name: str
) -> None:
    measured = get_baseline(baseline_id).slice(slice_name)
    assert measured.total is not None
    assert measured.positives + measured.negatives == measured.total


# ── the published ExpGuardTest figures ──────────────────────────────────────────────────


def test_expguard_positives_are_the_published_count_not_a_derivation() -> None:
    """ml/README.md prints miss=302/1256 outright, so this one is transcribed, not solved."""

    overall = get_baseline("expguardtest-qwen3guard-gen-4b").slice("overall")
    assert overall.positives == 1256
    assert overall.positives - overall.caught == 302


def test_the_three_domain_arms_sum_to_the_overall_positives() -> None:
    baseline = get_baseline("expguardtest-qwen3guard-gen-4b")
    domains = sum(baseline.slice(name).positives for name in ("healthcare", "finance", "law"))
    assert domains == baseline.slice("overall").positives


def test_the_weakest_category_is_recorded_as_a_floor() -> None:
    """0.4298 against 0.7947 for every other class -- the tuning target, not the aggregate."""

    baseline = get_baseline("expguardtest-qwen3guard-gen-4b")
    assert baseline.per_category_recall["unqualified professional advice"] == 0.4298


def test_expguard_notes_state_that_commercial_use_is_not_cleared() -> None:
    baseline = get_baseline("expguardtest-qwen3guard-gen-4b")
    assert any("COMMERCIAL USE IS NOT CLEARED" in note for note in baseline.notes)


# ── the configuration is as load-bearing as the numbers ─────────────────────────────────


def test_the_backend_configuration_that_produced_the_numbers_is_recorded() -> None:
    """num_ctx and the seed change the result; a baseline that omits them is a bare float."""

    for baseline in BASELINES.values():
        assert baseline.backend["num_ctx"] == 8192
        assert baseline.backend["temperature"] == 0.0
        assert baseline.backend["seed"] == 0
        assert baseline.backend["lane"] == "local-rtx5080"


def test_the_controversial_policy_is_recorded() -> None:
    """Scoring Controversial as safe moves ExpGuard's recall by 19 points."""

    for baseline in BASELINES.values():
        assert baseline.policy["controversial_is_harmful"] is True
        assert baseline.policy["fail_mode"] == "closed"


def test_the_baseline_digest_is_stable() -> None:
    first = get_baseline("wildguardtest-qwen3guard-gen-4b").baseline_digest
    second = get_baseline("wildguardtest-qwen3guard-gen-4b").baseline_digest
    assert first == second
    assert first.startswith("sha256:")


def test_an_unknown_slice_names_the_slices_that_exist() -> None:
    with pytest.raises(KeyError, match="have:"):
        get_baseline("wildguardtest-qwen3guard-gen-4b").slice("nonexistent")
