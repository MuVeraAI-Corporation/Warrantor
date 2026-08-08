"""Tests for aumos_sla: targets, recording, windowing, status, breaches."""

from __future__ import annotations

import pytest

from aumos_sla import SLAMonitor, SLAStatus, SLATarget


# ---------------------------------------------------------------------------
# SLATarget validation
# ---------------------------------------------------------------------------
def test_target_rejects_empty_name() -> None:
    with pytest.raises(ValueError):
        SLATarget("", threshold=1.0, window_seconds=60, comparison="lt")


def test_target_rejects_non_positive_window() -> None:
    with pytest.raises(ValueError):
        SLATarget("m", threshold=1.0, window_seconds=0, comparison="lt")


def test_target_rejects_invalid_comparison() -> None:
    with pytest.raises(ValueError):
        SLATarget("m", threshold=1.0, window_seconds=60, comparison="le")  # type: ignore[arg-type]


def test_target_satisfies_lt_gt_eq() -> None:
    lt = SLATarget("m", threshold=10, window_seconds=60, comparison="lt")
    gt = SLATarget("m", threshold=10, window_seconds=60, comparison="gt")
    eq = SLATarget("m", threshold=10, window_seconds=60, comparison="eq")
    assert lt.satisfies(5) and not lt.satisfies(10)
    assert gt.satisfies(20) and not gt.satisfies(10)
    assert eq.satisfies(10) and not eq.satisfies(9)


# ---------------------------------------------------------------------------
# Basic recording + status
# ---------------------------------------------------------------------------
def test_check_status_unknown_when_no_target() -> None:
    monitor = SLAMonitor()
    monitor.record_metric("nope", 1.0, timestamp=0.0)
    assert monitor.check_status("nope", now=0.0) is SLAStatus.UNKNOWN


def test_check_status_unknown_when_no_samples() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("m", threshold=10, window_seconds=60, comparison="lt"))
    assert monitor.check_status("m", now=100.0) is SLAStatus.UNKNOWN


def test_meeting_when_all_samples_below_threshold() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("latency_ms", threshold=500, window_seconds=60,
                                 comparison="lt"))
    monitor.record_metric("latency_ms", 100, timestamp=100.0)
    monitor.record_metric("latency_ms", 200, timestamp=110.0)
    monitor.record_metric("latency_ms", 499, timestamp=120.0)
    assert monitor.check_status("latency_ms", now=120.0) is SLAStatus.MEETING


def test_breaching_when_any_sample_violates() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("latency_ms", threshold=500, window_seconds=60,
                                 comparison="lt"))
    monitor.record_metric("latency_ms", 100, timestamp=100.0)
    monitor.record_metric("latency_ms", 600, timestamp=110.0)  # breach
    monitor.record_metric("latency_ms", 200, timestamp=120.0)
    assert monitor.check_status("latency_ms", now=120.0) is SLAStatus.BREACHING


def test_eq_comparison_strict() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("count", threshold=1, window_seconds=60,
                                 comparison="eq"))
    monitor.record_metric("count", 1, timestamp=0.0)
    monitor.record_metric("count", 2, timestamp=1.0)
    assert monitor.check_status("count", now=1.0) is SLAStatus.BREACHING


# ---------------------------------------------------------------------------
# Rolling window behavior
# ---------------------------------------------------------------------------
def test_old_samples_age_out_of_window() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("m", threshold=10, window_seconds=10,
                                 comparison="lt"))
    # Breaching sample from the past, outside the window now
    monitor.record_metric("m", 999, timestamp=0.0)
    # Aged out at now=100 (window ends at 90)
    assert monitor.check_status("m", now=100.0) is SLAStatus.UNKNOWN
    # Fresh good sample
    monitor.record_metric("m", 1, timestamp=95.0)
    assert monitor.check_status("m", now=100.0) is SLAStatus.MEETING


def test_pruning_drops_stale_samples() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("m", threshold=10, window_seconds=10,
                                 comparison="lt"))
    for ts in (0.0, 1.0, 2.0, 100.0):
        monitor.record_metric("m", 1, timestamp=ts)
    # First three are older than (100 - 10) = 90 and should be pruned.
    monitor.check_status("m", now=100.0)
    assert monitor.sample_count("m") == 1


# ---------------------------------------------------------------------------
# Multi-target / aggregate APIs
# ---------------------------------------------------------------------------
def test_check_all_and_active_breaches() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("good", threshold=10, window_seconds=60, comparison="lt"))
    monitor.add_target(SLATarget("bad", threshold=10, window_seconds=60, comparison="lt"))
    monitor.record_metric("good", 1, timestamp=0.0)
    monitor.record_metric("bad", 99, timestamp=0.0)
    statuses = monitor.check_all(now=0.0)
    assert statuses["good"] is SLAStatus.MEETING
    assert statuses["bad"] is SLAStatus.BREACHING
    assert monitor.active_breaches(now=0.0) == ["bad"]


def test_remove_target_clears_state() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("m", threshold=10, window_seconds=60, comparison="lt"))
    monitor.record_metric("m", 1, timestamp=0.0)
    assert monitor.remove_target("m") is True
    assert monitor.remove_target("m") is False  # already gone
    assert monitor.check_status("m", now=0.0) is SLAStatus.UNKNOWN
    assert monitor.sample_count("m") == 0


def test_record_metric_defaults_to_now() -> None:
    monitor = SLAMonitor()
    monitor.add_target(SLATarget("m", threshold=10, window_seconds=10,
                                 comparison="lt"))
    monitor.record_metric("m", 1)  # uses time.time()
    # Should immediately be MEETING
    assert monitor.check_status("m") is SLAStatus.MEETING


def test_record_metric_rejects_nan() -> None:
    monitor = SLAMonitor()
    with pytest.raises(ValueError):
        monitor.record_metric("m", float("nan"))


def test_add_target_rejects_non_target() -> None:
    monitor = SLAMonitor()
    with pytest.raises(TypeError):
        monitor.add_target("not_a_target")  # type: ignore[arg-type]


def test_thread_safe_concurrent_records() -> None:
    """Smoke test that concurrent writers don't corrupt state."""
    import threading

    monitor = SLAMonitor()
    monitor.add_target(SLATarget("m", threshold=10_000, window_seconds=1000,
                                 comparison="lt"))

    def writer() -> None:
        for i in range(200):
            monitor.record_metric("m", i, timestamp=float(i))

    threads = [threading.Thread(target=writer) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 4 threads * 200 samples = 800
    assert monitor.sample_count("m") == 800
    assert monitor.check_status("m", now=1000.0) is SLAStatus.MEETING
