"""Warrantor train-guard (S8) — training-time integrity monitor.

Hooks into the training loop (framework-agnostic: takes plain floats for gradients/losses, so it
works with PyTorch, JAX, TensorFlow, or any other framework) and checks:

  - **Gradient integrity**: NaN/Inf detection, explosion (norm > threshold), vanishing (norm ~ 0).
  - **Loss-curve sanity**: NaN/Inf detection, divergence (loss increasing for too many steps),
    plateau detection.
  - **Dependency integrity**: hashes the pinned package set; mismatches flag a tampered env.
  - **Weight-init sanity**: confirms the initial weight stats match the declared init scheme.

On completion, emits a signed training attestation that downstream components (S4 ModelSBOM,
S2 ProvenaChain) reference.

See ``docs/rfcs/S8-train-guard.md``.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class CheckStatus(str, Enum):
    """Result of one integrity check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class CheckType(str, Enum):
    """The kinds of checks train-guard runs."""

    GRADIENT_NAN_INF = "gradient_nan_inf"
    GRADIENT_EXPLOSION = "gradient_explosion"
    GRADIENT_VANISHING = "gradient_vanishing"
    LOSS_NAN_INF = "loss_nan_inf"
    LOSS_DIVERGENCE = "loss_divergence"
    DEPENDENCY_INTEGRITY = "dependency_integrity"
    WEIGHT_INIT_SANITY = "weight_init_sanity"


@dataclass
class CheckResult:
    """One integrity-check result."""

    type: CheckType
    status: CheckStatus
    detail: str
    step: int | None = None
    metric: float | None = None
    threshold: float | None = None


@dataclass
class TrainGuardConfig:
    """Configurable thresholds for train-guard."""

    gradient_explosion_threshold: float = 1000.0
    gradient_vanishing_threshold: float = 1e-8
    loss_divergence_patience: int = 20  # consecutive non-improving steps before WARN
    loss_divergence_fail_patience: int = 100  # consecutive non-improving steps before FAIL
    weight_init_tolerance: float = 0.1  # stddev relative tolerance


@dataclass
class WeightInitSpec:
    """The declared weight-initialization scheme, against which init sanity is checked."""

    scheme: str  # "xavier_uniform", "normal", "kaiming_normal", etc.
    expected_mean: float = 0.0
    expected_stddev: float = 0.02  # default for normal(0, 0.02)


@dataclass
class DependencySnapshot:
    """A snapshot of the pinned dependency set, hashed for integrity."""

    packages: dict[str, str]  # name → version
    digest: str = ""

    @classmethod
    def from_packages(cls, packages: dict[str, str]) -> DependencySnapshot:
        """Construct a snapshot, computing the digest (deterministic over sorted name=version)."""
        canon = "\n".join(f"{k}=={v}" for k, v in sorted(packages.items()))
        digest = "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()
        return cls(packages=dict(packages), digest=digest)

    def matches(self, other: DependencySnapshot) -> bool:
        """True if this snapshot's digest equals another's."""
        return self.digest == other.digest


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TrainGuard:
    """The training-loop monitor. Call ``on_step_end`` after every optimizer step and
    ``finalize`` at the end of training to emit the attestation."""

    def __init__(
        self,
        config: TrainGuardConfig | None = None,
        dependency_snapshot: DependencySnapshot | None = None,
        weight_init: WeightInitSpec | None = None,
    ) -> None:
        self.config = config or TrainGuardConfig()
        self.dependency_snapshot = dependency_snapshot
        self.weight_init = weight_init
        self.results: list[CheckResult] = []
        self._loss_history: list[float] = []
        self._best_loss: float | None = None
        self._steps_since_improvement = 0

    def check_gradient(self, gradient_norm: float, step: int) -> list[CheckResult]:
        """Run all gradient checks against the supplied per-step gradient norm.

        Returns the results (also appends them to ``self.results``).
        """
        out: list[CheckResult] = []
        if math.isnan(gradient_norm) or math.isinf(gradient_norm):
            r = CheckResult(
                CheckType.GRADIENT_NAN_INF,
                CheckStatus.FAIL,
                f"gradient_norm is {'NaN' if math.isnan(gradient_norm) else 'Inf'}",
                step=step,
                metric=gradient_norm,
            )
            out.append(r)
        elif gradient_norm > self.config.gradient_explosion_threshold:
            out.append(
                CheckResult(
                    CheckType.GRADIENT_EXPLOSION,
                    CheckStatus.FAIL,
                    f"gradient_norm {gradient_norm:.2e} > {self.config.gradient_explosion_threshold}",
                    step=step,
                    metric=gradient_norm,
                    threshold=self.config.gradient_explosion_threshold,
                )
            )
        elif gradient_norm < self.config.gradient_vanishing_threshold:
            out.append(
                CheckResult(
                    CheckType.GRADIENT_VANISHING,
                    CheckStatus.WARN,
                    f"gradient_norm {gradient_norm:.2e} < {self.config.gradient_vanishing_threshold}",
                    step=step,
                    metric=gradient_norm,
                    threshold=self.config.gradient_vanishing_threshold,
                )
            )
        self.results.extend(out)
        return out

    def check_loss(self, loss: float, step: int) -> list[CheckResult]:
        """Run loss-curve checks against the supplied per-step loss."""
        out: list[CheckResult] = []
        if math.isnan(loss) or math.isinf(loss):
            out.append(
                CheckResult(
                    CheckType.LOSS_NAN_INF,
                    CheckStatus.FAIL,
                    f"loss is {'NaN' if math.isnan(loss) else 'Inf'}",
                    step=step,
                    metric=loss,
                )
            )
            self.results.extend(out)
            self._loss_history.append(loss)
            return out

        # Track divergence.
        if self._best_loss is None or loss < self._best_loss:
            self._best_loss = loss
            self._steps_since_improvement = 0
        else:
            self._steps_since_improvement += 1
        self._loss_history.append(loss)

        if self._steps_since_improvement >= self.config.loss_divergence_fail_patience:
            out.append(
                CheckResult(
                    CheckType.LOSS_DIVERGENCE,
                    CheckStatus.FAIL,
                    f"no improvement for {self._steps_since_improvement} steps",
                    step=step,
                    metric=float(self._steps_since_improvement),
                    threshold=float(self.config.loss_divergence_fail_patience),
                )
            )
        elif self._steps_since_improvement >= self.config.loss_divergence_patience:
            out.append(
                CheckResult(
                    CheckType.LOSS_DIVERGENCE,
                    CheckStatus.WARN,
                    f"no improvement for {self._steps_since_improvement} steps",
                    step=step,
                    metric=float(self._steps_since_improvement),
                    threshold=float(self.config.loss_divergence_patience),
                )
            )
        self.results.extend(out)
        return out

    def check_weight_init(self, observed_mean: float, observed_stddev: float) -> CheckResult:
        """Compare observed initial weight stats to the declared scheme."""
        if self.weight_init is None:
            r = CheckResult(
                CheckType.WEIGHT_INIT_SANITY,
                CheckStatus.WARN,
                "no WeightInitSpec declared; skipping",
            )
            self.results.append(r)
            return r
        spec = self.weight_init
        mean_diff = abs(observed_mean - spec.expected_mean)
        # Relative stddev tolerance (guard against divide-by-zero).
        stddev_rel = (
            abs(observed_stddev - spec.expected_stddev) / spec.expected_stddev
            if spec.expected_stddev > 0
            else abs(observed_stddev - spec.expected_stddev)
        )
        if mean_diff > spec.expected_stddev or stddev_rel > self.config.weight_init_tolerance:
            r = CheckResult(
                CheckType.WEIGHT_INIT_SANITY,
                CheckStatus.FAIL,
                (
                    f"weight init mismatch: mean={observed_mean:.4f} (expected {spec.expected_mean}), "
                    f"stddev={observed_stddev:.4f} (expected {spec.expected_stddev})"
                ),
                metric=stddev_rel,
                threshold=self.config.weight_init_tolerance,
            )
        else:
            r = CheckResult(
                CheckType.WEIGHT_INIT_SANITY,
                CheckStatus.PASS,
                f"weight init matches {spec.scheme}",
            )
        self.results.append(r)
        return r

    def check_dependencies(self, current: DependencySnapshot) -> CheckResult:
        """Verify the current dependency snapshot matches the recorded one."""
        if self.dependency_snapshot is None:
            r = CheckResult(
                CheckType.DEPENDENCY_INTEGRITY,
                CheckStatus.WARN,
                "no baseline dependency snapshot recorded; skipping",
            )
        elif self.dependency_snapshot.matches(current):
            r = CheckResult(
                CheckType.DEPENDENCY_INTEGRITY,
                CheckStatus.PASS,
                f"dependency digest matches ({current.digest})",
            )
        else:
            r = CheckResult(
                CheckType.DEPENDENCY_INTEGRITY,
                CheckStatus.FAIL,
                f"dependency digest mismatch: expected {self.dependency_snapshot.digest}, got {current.digest}",
            )
        self.results.append(r)
        return r

    def on_step_end(self, *, loss: float, gradient_norm: float, step: int) -> list[CheckResult]:
        """Convenience: run both gradient + loss checks for a step."""
        return [*self.check_gradient(gradient_norm, step), *self.check_loss(loss, step)]

    def finalize(self, run_id: str, model_id: str) -> TrainingAttestation:
        """Emit the signed training attestation. The signature is added by T1 trust-core in
        production; this method produces the canonical JSON the attestation wraps."""
        return TrainingAttestation(
            run_id=run_id,
            model_id=model_id,
            emitted_at=_utcnow_iso(),
            results=list(self.results),
            final_loss=self._loss_history[-1] if self._loss_history else None,
            best_loss=self._best_loss,
            steps_completed=len(self._loss_history),
            dependency_digest=self.dependency_snapshot.digest if self.dependency_snapshot else None,
        )


@dataclass
class TrainingAttestation:
    """The training attestation emitted at the end of training. References by S4 ModelSBOM
    and S2 ProvenaChain."""

    run_id: str
    model_id: str
    emitted_at: str
    results: list[CheckResult]
    final_loss: float | None
    best_loss: float | None
    steps_completed: int
    dependency_digest: str | None

    @property
    def status(self) -> CheckStatus:
        """Aggregate status: FAIL dominates WARN dominates PASS."""
        statuses = {r.status for r in self.results}
        if CheckStatus.FAIL in statuses:
            return CheckStatus.FAIL
        if CheckStatus.WARN in statuses:
            return CheckStatus.WARN
        return CheckStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "model_id": self.model_id,
            "emitted_at": self.emitted_at,
            "status": self.status.value,
            "final_loss": self.final_loss,
            "best_loss": self.best_loss,
            "steps_completed": self.steps_completed,
            "dependency_digest": self.dependency_digest,
            "checks": [
                {
                    "type": r.type.value,
                    "status": r.status.value,
                    "detail": r.detail,
                    "step": r.step,
                    "metric": r.metric,
                    "threshold": r.threshold,
                }
                for r in self.results
            ],
        }


__all__ = [
    "CheckResult",
    "CheckStatus",
    "CheckType",
    "DependencySnapshot",
    "TrainGuard",
    "TrainGuardConfig",
    "TrainingAttestation",
    "WeightInitSpec",
]
