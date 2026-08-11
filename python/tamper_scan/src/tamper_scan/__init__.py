"""AumOS tamper-scan (S7) — the AI equivalent of a virus scanner.

Detects tampering in model weights via four analyzers:

  - **WeightDistribution**: flags tensors whose weight statistics deviate from a baseline
    (e.g. an injected backdoor often spikes outlier counts).
  - **BackdoorPatterns**: looks for high-magnitude clusters in specific tensor slices
    (the signature of a weight-based trigger).
  - **NeuronPruning**: detects a sudden drop in active (non-zero) neurons relative to baseline,
    which can indicate adversarial pruning.
  - **FineTuneDetection**: detects fine-tuning by comparing against a base model's weights
    (cosine-similarity drop in specific layers).

Pure-Python with optional numpy acceleration. See ``docs/rfcs/S7-tamper-scan.md``.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Optional numpy — used for fast statistics when present; pure-Python fallback otherwise.
try:
    import numpy as _np

    _HAVE_NUMPY = True
except ImportError:  # pragma: no cover
    _np = None
    _HAVE_NUMPY = False


class Severity(str, Enum):
    """Severity of a finding (mirrors cross-cutting 14-disclosure-policy)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    """The four tamper categories."""

    WEIGHT_DISTRIBUTION_ANOMALY = "weight_distribution_anomaly"
    BACKDOOR_PATTERN = "backdoor_pattern"
    NEURON_PRUNING = "neuron_pruning"
    FINE_TUNE_DETECTED = "fine_tune_detected"


@dataclass
class Finding:
    """One tamper-detection finding."""

    type: FindingType
    severity: Severity
    tensor_name: str
    detail: str
    metric: float | None = None
    threshold: float | None = None


@dataclass
class TensorStats:
    """Summary statistics for a single tensor (used as baseline or scan subject)."""

    name: str
    mean: float
    stddev: float
    min_val: float
    max_val: float
    outlier_fraction: float  # fraction of weights > 4 stddevs from mean
    sparsity: float  # fraction of weights == 0

    @classmethod
    def from_weights(cls, name: str, weights: list[float]) -> TensorStats:
        """Compute summary stats from a flat list of weights."""
        if not weights:
            return cls(name, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0)
        if _HAVE_NUMPY:
            arr = _np.asarray(weights, dtype=_np.float64)
            mean = float(arr.mean())
            stddev = float(arr.std())
            min_val = float(arr.min())
            max_val = float(arr.max())
            threshold = 4 * stddev if stddev > 0 else 0.0
            outlier = float((_np.abs(arr - mean) > threshold).mean())
            sparsity = float((arr == 0).mean())
            return cls(name, mean, stddev, min_val, max_val, outlier, sparsity)
        # Pure-Python fallback.
        mean = statistics.fmean(weights)
        stddev = statistics.pstdev(weights) if len(weights) > 1 else 0.0
        min_val = min(weights)
        max_val = max(weights)
        if stddev > 0:
            outliers = sum(1 for w in weights if abs(w - mean) > 4 * stddev)
            outlier = outliers / len(weights)
        else:
            outlier = 0.0
        zeros = sum(1 for w in weights if w == 0)
        sparsity = zeros / len(weights)
        return cls(name, mean, stddev, min_val, max_val, outlier, sparsity)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length vectors. Pure Python."""
    if len(a) != len(b) or not a:
        return 0.0
    if _HAVE_NUMPY:
        va, vb = _np.asarray(a), _np.asarray(b)
        na, nb = float(_np.linalg.norm(va)), float(_np.linalg.norm(vb))
        if na == 0 or nb == 0:
            return 0.0
        return float(_np.dot(va, vb) / (na * nb))
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


# --- Analyzer 1: weight-distribution anomalies -----------------------------
@dataclass
class WeightDistributionConfig:
    """Thresholds for the weight-distribution analyzer."""

    outlier_fraction_threshold: float = 0.05  # 5% beyond 4 standard deviations is suspicious
    stddev_ratio_threshold: float = 3.0  # stddev 3x baseline is suspicious


def scan_weight_distribution(
    baseline: dict[str, TensorStats],
    subject: dict[str, TensorStats],
    config: WeightDistributionConfig | None = None,
) -> list[Finding]:
    """Compare subject tensor stats against a baseline. Flag outliers and stddev spikes."""
    config = config or WeightDistributionConfig()
    findings: list[Finding] = []
    for name, sub in subject.items():
        base = baseline.get(name)
        if base is None:
            continue
        if sub.outlier_fraction > config.outlier_fraction_threshold:
            findings.append(
                Finding(
                    type=FindingType.WEIGHT_DISTRIBUTION_ANOMALY,
                    severity=Severity.MEDIUM,
                    tensor_name=name,
                    detail=f"outlier fraction {sub.outlier_fraction:.3f} > {config.outlier_fraction_threshold}",
                    metric=sub.outlier_fraction,
                    threshold=config.outlier_fraction_threshold,
                )
            )
        if base.stddev > 0 and sub.stddev / base.stddev > config.stddev_ratio_threshold:
            findings.append(
                Finding(
                    type=FindingType.WEIGHT_DISTRIBUTION_ANOMALY,
                    severity=Severity.HIGH,
                    tensor_name=name,
                    detail=f"stddev ratio {sub.stddev / base.stddev:.2f} > {config.stddev_ratio_threshold}",
                    metric=sub.stddev / base.stddev,
                    threshold=config.stddev_ratio_threshold,
                )
            )
    return findings


# --- Analyzer 2: backdoor-trigger patterns ---------------------------------
@dataclass
class BackdoorConfig:
    """Thresholds for the backdoor-pattern analyzer."""

    cluster_magnitude_threshold: float = (
        10.0  # |weight| > 10 is suspicious in a normally-scaled tensor
    )


def scan_backdoor_patterns(
    tensors: dict[str, list[float]],
    config: BackdoorConfig | None = None,
) -> list[Finding]:
    """Look for high-magnitude clusters (the signature of a weight-based trigger)."""
    config = config or BackdoorConfig()
    findings: list[Finding] = []
    for name, weights in tensors.items():
        if not weights:
            continue
        max_abs = max(abs(w) for w in weights)
        if max_abs > config.cluster_magnitude_threshold:
            findings.append(
                Finding(
                    type=FindingType.BACKDOOR_PATTERN,
                    severity=Severity.HIGH,
                    tensor_name=name,
                    detail=f"max |weight| {max_abs:.2f} > {config.cluster_magnitude_threshold}",
                    metric=max_abs,
                    threshold=config.cluster_magnitude_threshold,
                )
            )
    return findings


# --- Analyzer 3: neuron pruning --------------------------------------------
@dataclass
class NeuronPruningConfig:
    """Thresholds for the pruning analyzer."""

    sparsity_ratio_threshold: float = 2.0  # 2x baseline sparsity is suspicious
    absolute_sparsity_threshold: float = 0.5  # > 50% zeros


def scan_neuron_pruning(
    baseline: dict[str, TensorStats],
    subject: dict[str, TensorStats],
    config: NeuronPruningConfig | None = None,
) -> list[Finding]:
    """Detect a sudden drop in active (non-zero) neurons relative to baseline."""
    config = config or NeuronPruningConfig()
    findings: list[Finding] = []
    for name, sub in subject.items():
        base = baseline.get(name)
        if base is None:
            continue
        if base.sparsity > 0 and sub.sparsity / base.sparsity > config.sparsity_ratio_threshold:
            findings.append(
                Finding(
                    type=FindingType.NEURON_PRUNING,
                    severity=Severity.MEDIUM,
                    tensor_name=name,
                    detail=f"sparsity ratio {sub.sparsity / base.sparsity:.2f} > {config.sparsity_ratio_threshold}",
                    metric=sub.sparsity / base.sparsity,
                    threshold=config.sparsity_ratio_threshold,
                )
            )
        if sub.sparsity > config.absolute_sparsity_threshold:
            findings.append(
                Finding(
                    type=FindingType.NEURON_PRUNING,
                    severity=Severity.HIGH,
                    tensor_name=name,
                    detail=f"absolute sparsity {sub.sparsity:.2f} > {config.absolute_sparsity_threshold}",
                    metric=sub.sparsity,
                    threshold=config.absolute_sparsity_threshold,
                )
            )
    return findings


# --- Analyzer 4: fine-tune detection ---------------------------------------
@dataclass
class FineTuneConfig:
    """Threshold for fine-tune detection (cosine similarity drop)."""

    similarity_threshold: float = 0.95  # < 0.95 suggests fine-tuning


def scan_fine_tune(
    base_tensors: dict[str, list[float]],
    subject_tensors: dict[str, list[float]],
    config: FineTuneConfig | None = None,
) -> list[Finding]:
    """Detect fine-tuning by comparing per-tensor cosine similarity to a base model."""
    config = config or FineTuneConfig()
    findings: list[Finding] = []
    for name, subject in subject_tensors.items():
        base = base_tensors.get(name)
        if base is None or len(base) != len(subject) or not base:
            continue
        sim = _cosine_similarity(base, subject)
        if sim < config.similarity_threshold:
            findings.append(
                Finding(
                    type=FindingType.FINE_TUNE_DETECTED,
                    severity=Severity.LOW,
                    tensor_name=name,
                    detail=f"cosine similarity {sim:.3f} < {config.similarity_threshold}",
                    metric=sim,
                    threshold=config.similarity_threshold,
                )
            )
    return findings


@dataclass
class ScanReport:
    """Aggregate report from running all four analyzers."""

    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_or_high(self) -> list[Finding]:
        """Findings that must be filed per disclosure policy."""
        return [f for f in self.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_count": len(self.findings),
            "critical_or_high": len(self.critical_or_high),
            "findings": [
                {
                    "type": f.type.value,
                    "severity": f.severity.value,
                    "tensor": f.tensor_name,
                    "detail": f.detail,
                    "metric": f.metric,
                    "threshold": f.threshold,
                }
                for f in self.findings
            ],
        }


def scan(
    baseline_tensors: dict[str, list[float]] | None = None,
    subject_tensors: dict[str, list[float]] | None = None,
) -> ScanReport:
    """Run every applicable analyzer and return the aggregate report.

    Args:
        baseline_tensors: trusted baseline weights (optional — needed for distribution,
            pruning, and fine-tune comparisons).
        subject_tensors: the weights under test.
    """
    subject_tensors = subject_tensors or {}
    baseline_tensors = baseline_tensors or {}
    report = ScanReport()
    subject_stats = {n: TensorStats.from_weights(n, w) for n, w in subject_tensors.items()}
    baseline_stats = {n: TensorStats.from_weights(n, w) for n, w in baseline_tensors.items()}

    if baseline_stats:
        report.findings.extend(scan_weight_distribution(baseline_stats, subject_stats))
        report.findings.extend(scan_neuron_pruning(baseline_stats, subject_stats))
        report.findings.extend(scan_fine_tune(baseline_tensors, subject_tensors))
    report.findings.extend(scan_backdoor_patterns(subject_tensors))
    return report


__all__ = [
    "BackdoorConfig",
    "Finding",
    "FindingType",
    "FineTuneConfig",
    "NeuronPruningConfig",
    "ScanReport",
    "Severity",
    "TensorStats",
    "WeightDistributionConfig",
    "scan",
    "scan_backdoor_patterns",
    "scan_fine_tune",
    "scan_neuron_pruning",
    "scan_weight_distribution",
]
