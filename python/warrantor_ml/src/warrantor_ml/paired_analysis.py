"""Paired comparison of a candidate adapter against its baseline, on identical items.

# Why this exists

A recall delta is not a verdict. This repository has already paid for that lesson once: a
pre-registered monotonicity check fired on a 0.1867 -> 0.1600 dip and reported a reversal, and an
unregistered McNemar follow-up showed the step was **2 worse, 4 better, p = 0.688** -- noise
promoted to a headline because "is it larger" has no notion of sample size.

Two adapters measured on the same corpus are not two independent samples. They are the *same items*
scored twice, so the comparison that respects the design is a paired one over the items where the
two disagree. Unpaired comparisons discard that pairing and are under-powered.

# What it reports, and why each part is there

* **McNemar**, exact-binomial by default. The chi-square approximation with continuity correction is
  unreliable when discordant pairs are few, and few is exactly the regime these adapters live in --
  one comparison here has 11 discordant pairs in total.
* **The severity distribution**, alongside the recall verdict and never instead of it. A fine-tune
  can clear every recall and per-category bar while losing an entire output class: one adapter in
  this programme emitted **zero** `controversial` verdicts where its base emitted hundreds, and
  passed every stated criterion while doing so. Recall alone cannot see that.
* **A baseline-match assertion.** Comparing a 0.6B candidate against a 4B baseline is a
  size-mismatched comparison that looks perfectly well-formed. The caller must pass both files, and
  this module refuses to guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from math import comb
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PairedVerdict:
    """The outcome of one paired comparison, with the counts that produced it."""

    label: str
    #: Items the baseline caught and the candidate missed.
    baseline_only: int
    #: Items the candidate caught and the baseline missed.
    candidate_only: int
    #: Items both got right, and items both got wrong.
    both_caught: int
    both_missed: int
    #: Two-sided exact binomial p over the discordant pairs.
    p_value: float
    #: Severity value counts, candidate and baseline.
    candidate_severity: dict[str, int]
    baseline_severity: dict[str, int]

    @property
    def discordant(self) -> int:
        return self.baseline_only + self.candidate_only

    @property
    def severity_classes_lost(self) -> set[str]:
        """Severity values the baseline emits and the candidate never does.

        The failure this exists to surface. A class present in the baseline and absent in the
        candidate means the two models are not answering the same question, and no recall
        comparison between them is meaningful however the arithmetic lands.
        """
        return {k for k, v in self.baseline_severity.items() if v > 0} - {
            k for k, v in self.candidate_severity.items() if v > 0
        }

    @property
    def verdict(self) -> str:
        if self.severity_classes_lost:
            return "VOID -- candidate lost a severity class"
        if self.p_value >= 0.05:
            return "within noise"
        return "candidate better" if self.candidate_only > self.baseline_only else "baseline better"


def exact_mcnemar(baseline_only: int, candidate_only: int) -> float:
    """Two-sided exact binomial p over discordant pairs.

    Under the null, each discordant pair is equally likely to fall either way, so the count is
    Binomial(n, 0.5). Exact rather than chi-square because these comparisons routinely have fewer
    than 25 discordant pairs, where the approximation is not trustworthy -- and a p-value that is
    wrong in the permissive direction is exactly how noise becomes a finding.
    """
    n = baseline_only + candidate_only
    if n == 0:
        return 1.0
    k = min(baseline_only, candidate_only)
    tail = sum(comb(n, i) for i in range(k + 1)) / (2**n)
    return min(1.0, 2 * tail)


def _samples(path: Path) -> dict[str, dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    samples = document.get("samples")
    if not isinstance(samples, list):
        raise ValueError(f"{path} has no `samples` list; it cannot be compared item by item")
    return {s["sample_id"]: s for s in samples}


def _severity(samples: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sample in samples.values():
        key = str(sample.get("severity"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def compare(candidate_path: Path, baseline_path: Path, label: str) -> PairedVerdict:
    """Pair a candidate against a baseline on shared item ids, over the positives only.

    Recall is a statement about the positives, so the discordance that matters is measured there.
    Items either file failed to classify are excluded rather than counted as misses -- a backend
    that was down is a failed measurement, not a guard with poor recall.
    """
    candidate = _samples(candidate_path)
    baseline = _samples(baseline_path)
    shared = sorted(set(candidate) & set(baseline))
    if not shared:
        raise ValueError(
            f"{candidate_path.name} and {baseline_path.name} share no sample ids. They were "
            "probably measured on different corpora, and no paired comparison is possible."
        )

    baseline_only = candidate_only = both_caught = both_missed = 0
    for item in shared:
        c, b = candidate[item], baseline[item]
        if not b.get("expected_unsafe"):
            continue
        if c.get("errored") or b.get("errored"):
            continue
        cc, bc = bool(c.get("predicted_unsafe")), bool(b.get("predicted_unsafe"))
        if bc and not cc:
            baseline_only += 1
        elif cc and not bc:
            candidate_only += 1
        elif cc and bc:
            both_caught += 1
        else:
            both_missed += 1

    return PairedVerdict(
        label=label,
        baseline_only=baseline_only,
        candidate_only=candidate_only,
        both_caught=both_caught,
        both_missed=both_missed,
        p_value=exact_mcnemar(baseline_only, candidate_only),
        candidate_severity=_severity(candidate),
        baseline_severity=_severity(baseline),
    )


def render(verdict: PairedVerdict) -> str:
    """A human-readable block. Severity is printed whether or not it changed."""
    lines = [
        f"== {verdict.label}",
        f"   baseline-only {verdict.baseline_only}   candidate-only {verdict.candidate_only}   "
        f"both caught {verdict.both_caught}   both missed {verdict.both_missed}",
        f"   discordant {verdict.discordant}   exact two-sided p = {verdict.p_value:.4f}",
        f"   VERDICT: {verdict.verdict}",
        f"   severity candidate: {dict(sorted(verdict.candidate_severity.items()))}",
        f"   severity baseline : {dict(sorted(verdict.baseline_severity.items()))}",
    ]
    lost = verdict.severity_classes_lost
    if lost:
        lines.append(
            f"   *** CLASS LOST: {sorted(lost)} present in the baseline, absent in the candidate. "
            "The recall comparison above is not meaningful: these are different instruments."
        )
    return "\n".join(lines)
