"""AumOS SLA Monitor — rolling-window SLA tracking and breach alerting.

Records metric samples and evaluates them against ``SLATarget`` definitions.
Each target specifies a metric name, a numeric threshold, a comparison
operator (``lt``, ``gt``, ``eq``) and a rolling window in seconds. A target is
*meeting* the SLA if **every** sample inside the rolling window satisfies the
comparison, and *breaching* if **any** sample violates it.

Typical AumOS metrics:
  - ``inference.p99_latency_ms``   threshold 500, comparison ``lt`` (latency SLA)
  - ``killswitch.trigger_to_kill_s`` threshold 5, comparison ``lt`` (R3)
  - ``evidence.commit_lag_s``      threshold 60, comparison ``lt`` (I-07)
  - ``attestation.verify_success_rate`` threshold 0.99, comparison ``gt``

Usage:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("p99_latency_ms", threshold=500,
                                 window_seconds=60, comparison="lt"))
    monitor.record_metric("p99_latency_ms", 410, timestamp=time.time())
    assert monitor.check_status("p99_latency_ms") is SLAStatus.MEETING
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

Comparison = Literal["lt", "gt", "eq"]
_VALID_COMPARISONS = frozenset({"lt", "gt", "eq"})


class SLAStatus(str, Enum):
    """Outcome of an SLA evaluation."""

    MEETING = "meeting"
    BREACHING = "breaching"
    UNKNOWN = "unknown"  # no target registered, or no samples in the window


@dataclass(frozen=True)
class SLATarget:
    """A single SLA definition.

    Attributes:
        metric_name:      name of the metric this target applies to.
        threshold:        numeric boundary value.
        window_seconds:   how far back (in seconds) to look when evaluating.
        comparison:       ``lt`` (value < threshold), ``gt`` (value > threshold),
                          ``eq`` (value == threshold).
    """

    metric_name: str
    threshold: float
    window_seconds: float
    comparison: Comparison = "lt"

    def __post_init__(self) -> None:
        if not self.metric_name:
            raise ValueError("metric_name must be a non-empty string")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.comparison not in _VALID_COMPARISONS:
            raise ValueError(
                f"comparison must be one of {sorted(_VALID_COMPARISONS)}, "
                f"got {self.comparison!r}"
            )

    def satisfies(self, value: float) -> bool:
        """Return ``True`` if a single ``value`` meets this target."""
        if self.comparison == "lt":
            return value < self.threshold
        if self.comparison == "gt":
            return value > self.threshold
        return value == self.threshold


@dataclass
class _MetricSample:
    """Internal rolling-window sample."""

    value: float
    timestamp: float


@dataclass
class SLAMonitor:
    """Thread-safe rolling-window SLA monitor.

    The monitor keeps a per-metric deque of ``(value, timestamp)`` samples and
    prunes them lazily on every read. Memory is bounded in practice by the
    rate at which ``record_metric`` is called and the window length.
    """

    targets: dict[str, SLATarget] = field(default_factory=dict)
    _samples: dict[str, deque[_MetricSample]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------
    def add_target(self, target: SLATarget) -> None:
        """Register or replace an SLA target for ``target.metric_name``."""
        if not isinstance(target, SLATarget):
            raise TypeError("target must be an SLATarget instance")
        with self._lock:
            self.targets[target.metric_name] = target
            # Preserve existing samples when re-defining a target.
            self._samples.setdefault(target.metric_name, deque())

    def remove_target(self, metric_name: str) -> bool:
        """Remove the target for ``metric_name``. Returns ``True`` if it existed."""
        with self._lock:
            existed = self.targets.pop(metric_name, None) is not None
            self._samples.pop(metric_name, None)
            return existed

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------
    def record_metric(self, name: str, value: float, timestamp: float | None = None) -> None:
        """Record a single ``value`` for metric ``name`` at ``timestamp``.

        If ``timestamp`` is ``None`` the current wall-clock time is used.
        """
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        # Reject NaN/inf which would silently break comparisons.
        if not isinstance(value, int | float):
            raise TypeError("value must be numeric")
        if value != value:  # NaN check
            raise ValueError("value must not be NaN")
        if timestamp is None:
            timestamp = time.time()
        with self._lock:
            self._samples.setdefault(name, deque()).append(
                _MetricSample(value=float(value), timestamp=float(timestamp))
            )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def _pruned_samples(self, name: str, now: float) -> list[_MetricSample]:
        """Return samples inside the window, dropping stale ones in place."""
        target = self.targets.get(name)
        if target is None:
            return []
        dq = self._samples.get(name)
        if not dq:
            return []
        cutoff = now - target.window_seconds
        # Drop stale from the left (samples are appended in time order).
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()
        return list(dq)

    def check_status(self, name: str, now: float | None = None) -> SLAStatus:
        """Evaluate the SLA for ``name``.

        Returns ``UNKNOWN`` if there is no target registered for ``name`` or
        no samples fall inside the window. Otherwise returns ``MEETING`` if
        every in-window sample satisfies the target, or ``BREACHING`` if any
        sample violates it.
        """
        if now is None:
            now = time.time()
        with self._lock:
            target = self.targets.get(name)
            if target is None:
                return SLAStatus.UNKNOWN
            samples = self._pruned_samples(name, now)
        if not samples:
            return SLAStatus.UNKNOWN
        for sample in samples:
            if not target.satisfies(sample.value):
                return SLAStatus.BREACHING
        return SLAStatus.MEETING

    def check_all(self, now: float | None = None) -> dict[str, SLAStatus]:
        """Evaluate every registered target. Returns a fresh dict."""
        if now is None:
            now = time.time()
        with self._lock:
            names = list(self.targets.keys())
        return {name: self.check_status(name, now=now) for name in names}

    def active_breaches(self, now: float | None = None) -> list[str]:
        """Return the sorted list of metric names currently breaching."""
        return sorted(
            name
            for name, status in self.check_all(now=now).items()
            if status is SLAStatus.BREACHING
        )

    # ------------------------------------------------------------------
    # Introspection (useful for dashboards / tests)
    # ------------------------------------------------------------------
    def sample_count(self, name: str) -> int:
        """Number of samples currently stored for ``name`` (any age)."""
        with self._lock:
            return len(self._samples.get(name, ()))


__all__ = ["Comparison", "SLAMonitor", "SLAStatus", "SLATarget"]
