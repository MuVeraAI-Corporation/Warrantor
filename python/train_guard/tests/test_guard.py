"""Tests for train_guard: gradient, loss, dependency, weight-init, attestation."""

from __future__ import annotations

import math

from train_guard import (
    CheckStatus,
    CheckType,
    DependencySnapshot,
    TrainGuard,
    TrainGuardConfig,
    WeightInitSpec,
)


def test_gradient_nan_fails() -> None:
    g = TrainGuard()
    res = g.check_gradient(math.nan, step=1)
    assert res[0].type is CheckType.GRADIENT_NAN_INF
    assert res[0].status is CheckStatus.FAIL


def test_gradient_explosion_fails() -> None:
    g = TrainGuard(TrainGuardConfig(gradient_explosion_threshold=100.0))
    res = g.check_gradient(500.0, step=1)
    assert any(r.type is CheckType.GRADIENT_EXPLOSION and r.status is CheckStatus.FAIL for r in res)


def test_gradient_vanishing_warns() -> None:
    g = TrainGuard()
    res = g.check_gradient(1e-12, step=1)
    assert any(r.type is CheckType.GRADIENT_VANISHING and r.status is CheckStatus.WARN for r in res)


def test_gradient_clean_passes_silently() -> None:
    g = TrainGuard()
    res = g.check_gradient(1.0, step=1)
    assert res == []  # clean gradient → no finding


def test_loss_nan_fails() -> None:
    g = TrainGuard()
    res = g.check_loss(math.inf, step=1)
    assert any(r.type is CheckType.LOSS_NAN_INF and r.status is CheckStatus.FAIL for r in res)


def test_loss_divergence_warns_then_fails() -> None:
    cfg = TrainGuardConfig(loss_divergence_patience=2, loss_divergence_fail_patience=4)
    g = TrainGuard(cfg)
    g.check_loss(1.0, step=0)  # initial best
    g.check_loss(1.0, step=1)
    g.check_loss(1.0, step=2)
    res_step3 = g.check_loss(1.0, step=3)
    assert any(r.status is CheckStatus.WARN for r in res_step3)
    g.check_loss(1.0, step=4)
    res_step5 = g.check_loss(1.0, step=5)
    assert any(r.status is CheckStatus.FAIL for r in res_step5)


def test_loss_improvement_resets_counter() -> None:
    cfg = TrainGuardConfig(loss_divergence_patience=2)
    g = TrainGuard(cfg)
    g.check_loss(1.0, step=0)
    g.check_loss(1.0, step=1)
    g.check_loss(1.0, step=2)
    assert g._steps_since_improvement == 2
    g.check_loss(0.5, step=3)  # new best
    assert g._steps_since_improvement == 0


def test_dependency_mismatch_fails() -> None:
    snap1 = DependencySnapshot.from_packages({"torch": "2.3.0", "transformers": "4.40.0"})
    snap2 = DependencySnapshot.from_packages({"torch": "2.3.0", "transformers": "4.41.0"})
    assert snap1.digest != snap2.digest
    g = TrainGuard(dependency_snapshot=snap1)
    r = g.check_dependencies(snap2)
    assert r.status is CheckStatus.FAIL


def test_dependency_match_passes() -> None:
    snap = DependencySnapshot.from_packages({"torch": "2.3.0"})
    g = TrainGuard(dependency_snapshot=snap)
    r = g.check_dependencies(snap)
    assert r.status is CheckStatus.PASS


def test_weight_init_match_passes() -> None:
    spec = WeightInitSpec(scheme="normal", expected_mean=0.0, expected_stddev=0.02)
    g = TrainGuard(weight_init=spec)
    r = g.check_weight_init(observed_mean=0.001, observed_stddev=0.021)
    assert r.status is CheckStatus.PASS


def test_weight_init_mismatch_fails() -> None:
    spec = WeightInitSpec(scheme="normal", expected_mean=0.0, expected_stddev=0.02)
    g = TrainGuard(weight_init=spec)
    r = g.check_weight_init(observed_mean=1.0, observed_stddev=0.5)
    assert r.status is CheckStatus.FAIL


def test_attestation_aggregate_status_fail_dominates() -> None:
    g = TrainGuard()
    g.check_loss(1.0, step=0)
    g.check_gradient(math.nan, step=1)  # FAIL
    att = g.finalize("run-1", "model-1")
    assert att.status is CheckStatus.FAIL


def test_attestation_to_dict_includes_all_checks() -> None:
    g = TrainGuard()
    g.check_loss(1.0, step=0)
    g.check_gradient(0.5, step=0)
    att = g.finalize("run-1", "model-1")
    d = att.to_dict()
    assert d["run_id"] == "run-1"
    assert d["steps_completed"] == 1
    assert isinstance(d["checks"], list)


def test_on_step_end_runs_both_checks() -> None:
    g = TrainGuard()
    res = g.on_step_end(loss=1.0, gradient_norm=0.5, step=0)
    # Both clean → no findings.
    assert res == []


def test_dependency_snapshot_deterministic() -> None:
    a = DependencySnapshot.from_packages({"b": "1.0", "a": "2.0"})
    b = DependencySnapshot.from_packages({"a": "2.0", "b": "1.0"})  # different input order
    assert a.digest == b.digest
