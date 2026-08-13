"""Binomial statistics shared by the vertical benchmarks and the parity gate.

This module exists because two parts of one harness were about to start disagreeing about
whether a seven-point gap is real. :mod:`warrantor_ml.benchmark_expguard` already built and
proved a Wilson interval and a pooled two-proportion z on measured numbers; the promotion gate
in :mod:`warrantor_ml.parity` needs exactly that machinery to decide whether a candidate
adapter beat its baseline. Re-implementing it there would produce a second arithmetic that can
drift from the one the published per-domain table was computed with.

The addition over what the benchmark already had is :func:`minimum_detectable_delta`. A gate
that reports "within noise" without saying *how big a gap this eval set could have detected*
invites the reading that the model did not improve, when the true statement is often that the
evaluation was too small to tell. Those are different findings and only one of them is about
the model.
"""

from __future__ import annotations

import math
from typing import Literal

__all__ = [
    "Verdict",
    "minimum_detectable_delta",
    "significant_improvement",
    "two_proportion_z",
    "wilson_interval",
]

#: The answer a two-sided comparison is allowed to give. ``within_noise`` is a real answer, not
#: a failure to compute one, and the gate is required to be able to say it.
Verdict = Literal["improved", "within_noise", "regressed"]

#: Two-sided 95%. Pinned as a name so a caller widening the test has to say so at the call site.
Z_95 = 1.96


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion, as ``(low, high)``.

    Wilson rather than the normal approximation because guard recall lives near the top of the
    range, where the normal interval runs past 1.0 and stops meaning anything. Returns
    ``(0.0, 1.0)`` for zero trials -- no evidence is not an estimate, and reporting a point
    estimate of 0.0 for an empty arm is how an empty slice becomes a claim.
    """

    if trials <= 0:
        return (0.0, 1.0)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (proportion + z * z / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(proportion * (1 - proportion) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def two_proportion_z(
    successes_a: int,
    trials_a: int,
    successes_b: int,
    trials_b: int,
) -> float | None:
    """Pooled two-proportion z statistic, or ``None`` when either arm has no trials.

    ``None`` rather than 0.0 for an empty arm: zero is the statistic you get when two arms
    genuinely agree, and an empty arm agrees with nothing.
    """

    if trials_a <= 0 or trials_b <= 0:
        return None
    pooled = (successes_a + successes_b) / (trials_a + trials_b)
    variance = pooled * (1 - pooled) * (1 / trials_a + 1 / trials_b)
    if variance <= 0:
        return 0.0
    return ((successes_a / trials_a) - (successes_b / trials_b)) / math.sqrt(variance)


def significant_improvement(
    baseline_successes: int,
    baseline_trials: int,
    candidate_successes: int,
    candidate_trials: int,
    z: float = Z_95,
) -> Verdict:
    """Did the candidate beat the baseline beyond sampling noise, or fall behind it?

    Two-sided on purpose. A one-sided "did it improve" test collapses *got worse* and
    *indistinguishable* into one bucket, and those call for opposite actions: one is a
    regression to investigate, the other is an eval set to enlarge.

    An empty arm is ``within_noise``. No trials is no evidence, in either direction.
    """

    statistic = two_proportion_z(
        candidate_successes, candidate_trials, baseline_successes, baseline_trials
    )
    if statistic is None or abs(statistic) < z:
        return "within_noise"
    return "improved" if statistic > 0 else "regressed"


def minimum_detectable_delta(
    trials: int,
    baseline_rate: float = 0.5,
    z: float = Z_95,
) -> float:
    """The smallest proportion difference this many trials could resolve, roughly.

    Returns 1.0 for a non-positive trial count: with no samples nothing short of a total
    reversal is detectable, and 1.0 is the honest way to say that in the same units.

    Used by the gate to turn "within noise" into a sentence an operator can act on -- *this set
    of 40 could not have detected anything under 22 points, so the run proved nothing about a
    claimed 3-point gain*. ``baseline_rate=0.5`` is the conservative default because the
    binomial variance is maximised there; pass the measured baseline recall for a tighter and
    more honest figure.
    """

    if trials <= 0:
        return 1.0
    rate = min(max(baseline_rate, 0.0), 1.0)
    # Two equal-sized arms, pooled variance at `rate`. This is a planning approximation in the
    # same spirit as the VRAM estimator: good enough to refuse an underpowered comparison,
    # never a substitute for reporting the interval itself.
    variance = 2.0 * rate * (1.0 - rate) / trials
    return min(1.0, z * math.sqrt(variance))
