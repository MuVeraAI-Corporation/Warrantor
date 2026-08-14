"""The statistics the parity gate rests on, including the answers it must be able to refuse."""

from __future__ import annotations

from warrantor_ml import benchmark_expguard as be
from warrantor_ml import stats


def test_benchmark_expguard_still_exports_the_hoisted_helpers() -> None:
    """The vertical benchmark's 363-line test file imports these by their original names.

    Hoisting the arithmetic into `stats` must not move it out from under the module that proved
    it on real numbers -- two copies would be the drift this consolidation exists to prevent.
    """

    assert be.wilson_interval is stats.wilson_interval
    assert be._two_proportion_z is stats.two_proportion_z


def test_wilson_interval_brackets_the_estimate_and_stays_in_range() -> None:
    low, high = stats.wilson_interval(90, 100)
    assert low < 0.9 < high
    assert low >= 0.0 and high <= 1.0
    assert stats.wilson_interval(100, 100)[1] <= 1.0


def test_wilson_interval_reports_ignorance_rather_than_an_estimate_at_zero_trials() -> None:
    assert stats.wilson_interval(0, 0) == (0.0, 1.0)


def test_two_proportion_z_is_none_for_an_empty_arm() -> None:
    """None rather than 0.0: zero is what two agreeing arms produce, and nothing agrees."""

    assert stats.two_proportion_z(5, 10, 0, 0) is None
    assert stats.two_proportion_z(0, 0, 5, 10) is None


def test_significant_improvement_is_two_sided() -> None:
    """A regression must be reported as a regression, not folded into 'did not improve'."""

    # 850/1000 -> 920/1000 is a real gain at these counts.
    assert stats.significant_improvement(850, 1000, 920, 1000) == "improved"
    # The same gap in the other direction is a regression, not noise.
    assert stats.significant_improvement(920, 1000, 850, 1000) == "regressed"


def test_a_small_gap_over_a_large_sample_is_still_noise() -> None:
    assert stats.significant_improvement(850, 1000, 856, 1000) == "within_noise"


def test_a_large_gap_over_a_tiny_sample_is_noise() -> None:
    """The case the gate exists to refuse: 40 samples cannot support a promotion."""

    assert stats.significant_improvement(30, 40, 34, 40) == "within_noise"


def test_empty_arms_are_within_noise_not_an_improvement() -> None:
    assert stats.significant_improvement(0, 0, 10, 10) == "within_noise"


def test_minimum_detectable_delta_shrinks_with_sample_size() -> None:
    assert stats.minimum_detectable_delta(40) > stats.minimum_detectable_delta(1000)


def test_minimum_detectable_delta_is_total_ignorance_at_zero_trials() -> None:
    """1.0 says 'nothing short of a total reversal' in the same units as the answer."""

    assert stats.minimum_detectable_delta(0) == 1.0


def test_minimum_detectable_delta_explains_a_within_noise_verdict() -> None:
    """The number the gate quotes when it says an eval set was too small to tell.

    40 positives near the measured 0.8554 baseline cannot resolve the ~4-point gain a fine-tune
    is expected to produce, and that is a statement about the eval, not about the model.
    """

    detectable = stats.minimum_detectable_delta(40, baseline_rate=0.8554)
    assert detectable > 0.04
