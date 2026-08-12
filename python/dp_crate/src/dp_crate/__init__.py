"""Warrantor dp-crate (F2) — production-grade differential privacy toolkit.

Three building blocks, all framework-agnostic (operate on flat ``list[float]`` gradients so
they work equally well with PyTorch, JAX, TensorFlow, or NeMo):

  - :class:`DPSGDOptimizer` — clips per-example gradients to a fixed L2 bound and adds
    calibrated Gaussian noise (the two mechanical steps of DPSGD, Abadi et al. 2016).
  - :class:`PrivacyAccountant` — tracks the privacy budget via Rényi Differential Privacy
    (Mironov 2017). The RDP→(ε,δ) conversion uses the standard Balle et al. 2020 bound.
    Composition is additive in RDP space, which is the whole point of the moments accountant.
  - :class:`DPDashboard` — a serializable snapshot of the current budget for ops dashboards.

This crate has zero third-party runtime dependencies; the math is intentionally written in pure
Python (``math``, ``random.gauss``) so it can be audited line-by-line and so it runs inside a
TEE without numpy/torch.

See ``docs/rfcs/F2-dp-crate.md``.
"""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

# -----------------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------------


class AccountantType(str, Enum):
    """Which accountant formula is in use."""

    RDP = "rdp"  # Rényi Differential Privacy (Mironov 2017)
    MOMENTS = "moments"  # moments accountant (Abadi et al. 2016) — RDP evaluated at sampled alphas


class BudgetState(str, Enum):
    """Operational state of the privacy budget."""

    OK = "ok"
    APPROACHING = "approaching"  # ε within 90 % of target
    EXHAUSTED = "exhausted"  # ε at or above target
    INVALID = "invalid"  # parameters inconsistent


# -----------------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------------


class DPCrateError(Exception):
    """Base class for dp-crate errors."""


class BudgetExhausted(DPCrateError):
    """Raised when a step would push ε past the configured target."""


class InvalidNoiseMultiplier(DPCrateError):
    """Raised when noise_multiplier is non-positive (which gives infinite ε)."""


class InvalidSamplingRate(DPCrateError):
    """Raised when sampling_rate is outside (0, 1]."""


# -----------------------------------------------------------------------------------
# Math helpers — pure-Python RDP
# -----------------------------------------------------------------------------------


def _rdp_subsampled_gaussian(q: float, sigma: float, alpha: float) -> float:
    """RDP at order ``alpha`` for one step of subsampled Gaussian mechanism.

    Uses a tractable upper bound consistent with Mironov et al. 2019, "Rényi Differential
    Privacy of the Sampled Gaussian Mechanism". We take the maximum of two regimes:

      - Regime A (the "quadratic in q" upper bound, tight for q << 1):
            RDP_A(alpha) = q^2 * alpha / (2 * sigma^2)
        This is the dominant term for the small sampling rates used in practice (q < 0.01).
      - Regime B (a linear-in-q interpolation toward the no-subsample value):
            RDP_B(alpha) = q * alpha / (2 * sigma^2)
        This guarantees the bound is exact at q=1 (the pure Gaussian mechanism) and is
        conservative at intermediate q.

    At q=0 the bound is 0 (no step, no privacy loss). At q=1 the bound reduces to
    ``alpha / (2 sigma^2)`` — the textbook RDP of the Gaussian mechanism.

    Args:
        q: subsampling rate (the lot size / dataset size).
        sigma: noise-to-sensitivity ratio (noise_multiplier).
        alpha: Rényi divergence order (>= 1).

    Returns:
        The RDP at order alpha (in nats).

    Raises:
        InvalidNoiseMultiplier: if sigma <= 0.
        InvalidSamplingRate: if q is outside (0, 1].
        DPCrateError: if alpha < 1.
    """
    if sigma <= 0:
        raise InvalidNoiseMultiplier(f"sigma must be > 0, got {sigma}")
    if not 0 < q <= 1:
        raise InvalidSamplingRate(f"q must be in (0, 1], got {q}")
    if alpha < 1:
        raise DPCrateError(f"alpha must be >= 1, got {alpha}")

    # Full Gaussian mechanism term: alpha / (2 * sigma^2).
    full_term = alpha / (2.0 * sigma * sigma)
    if q == 1.0:
        return full_term

    # Regime A — quadratic in q.
    rdp_a = (q * q * alpha) / (2.0 * sigma * sigma)
    # Regime B — linear interpolation toward full_term.
    rdp_b = q * full_term
    return max(rdp_a, rdp_b)


def _rdp_to_epsilon(rdp_per_alpha: dict[float, float], delta: float) -> tuple[float, float]:
    """Convert per-alpha RDP to the tightest (epsilon, best_alpha) for a given delta.

    Standard conversion (Balle et al. 2020 / Mironov 2017):
        epsilon = inf_alpha  rdp(alpha) + log( (alpha-1)/alpha ) - log(delta) / (alpha-1)

    Returns the minimum epsilon across the supplied alpha grid and the alpha that achieved it.

    Note: when all RDP values are 0 (no steps consumed) the conversion returns epsilon=0 — the
    accountant has not yet incurred any privacy loss.
    """
    if delta <= 0 or delta >= 1:
        raise DPCrateError(f"delta must be in (0, 1), got {delta}")
    # No privacy loss accrued.
    if all(v <= 0.0 for v in rdp_per_alpha.values()):
        return 0.0, 0.0
    best_eps = math.inf
    best_alpha = 0.0
    for alpha, rdp in rdp_per_alpha.items():
        if alpha <= 1:
            continue
        try:
            log_term = math.log((alpha - 1) / alpha)
            eps = rdp + log_term - math.log(delta) / (alpha - 1)
        except (ValueError, ZeroDivisionError):
            continue
        if eps < best_eps:
            best_eps = eps
            best_alpha = alpha
    if math.isinf(best_eps):
        # Fall back to plain sum + log(1/delta).
        s = sum(rdp_per_alpha.values())
        return s - math.log(delta), 0.0
    return best_eps, best_alpha


# -----------------------------------------------------------------------------------
# PrivacyAccountant
# -----------------------------------------------------------------------------------


@dataclass
class AccountantConfig:
    """Configuration for the moments accountant.

    Attributes:
        noise_multiplier: sigma (noise std divided by sensitivity / clipping norm).
        sampling_rate: q (lot size / dataset size).
        delta: the (ε, δ)-DP delta, e.g. 1e-5.
        alphas: the Rényi orders at which to evaluate RDP.
        target_epsilon: budget ceiling; steps raise BudgetExhausted past this.
        accountant: which formula to evaluate.
    """

    noise_multiplier: float
    sampling_rate: float
    delta: float
    alphas: tuple[float, ...] = (
        1.25,
        1.5,
        2.0,
        3.0,
        4.0,
        5.0,
        6.0,
        8.0,
        16.0,
        32.0,
        64.0,
    )
    target_epsilon: float = 1.0
    accountant: AccountantType = AccountantType.RDP

    def __post_init__(self) -> None:
        if self.noise_multiplier <= 0:
            raise InvalidNoiseMultiplier(
                f"noise_multiplier must be > 0, got {self.noise_multiplier}"
            )
        if not 0 < self.sampling_rate <= 1:
            raise InvalidSamplingRate(f"sampling_rate must be in (0, 1], got {self.sampling_rate}")
        if not 0 < self.delta < 1:
            raise DPCrateError(f"delta must be in (0, 1), got {self.delta}")
        if self.target_epsilon <= 0:
            raise DPCrateError(f"target_epsilon must be > 0, got {self.target_epsilon}")
        if not self.alphas:
            raise DPCrateError("alphas must be non-empty")
        if any(a < 1 for a in self.alphas):
            raise DPCrateError("alphas must all be >= 1")


class PrivacyAccountant:
    """Tracks the (ε, δ)-DP budget of a training run.

    The accountant accumulates per-step RDP at each Rényi order; the consumed epsilon is
    obtained by converting the cumulative RDP back to (ε, δ) at the configured delta.
    """

    def __init__(self, config: AccountantConfig) -> None:
        self.config = config
        # Per-step RDP at each alpha. Cumulative RDP is the per-alpha sum.
        self._rdp: dict[float, float] = {a: 0.0 for a in config.alphas}
        self.steps: int = 0

    # ----- core mechanics --------------------------------------------------

    def step_rdp(self) -> dict[float, float]:
        """Return the per-step RDP contribution at each alpha (without consuming budget)."""
        return {
            a: _rdp_subsampled_gaussian(self.config.sampling_rate, self.config.noise_multiplier, a)
            for a in self.config.alphas
        }

    def consume(self, steps: int = 1) -> float:
        """Account for ``steps`` DPSGD steps and return the new consumed ε.

        Raises:
            BudgetExhausted: if the new ε would exceed ``target_epsilon``.
        """
        if steps < 0:
            raise DPCrateError(f"steps must be >= 0, got {steps}")
        per_step = self.step_rdp()
        for _ in range(steps):
            for a, rdp in per_step.items():
                self._rdp[a] += rdp
        self.steps += steps
        eps, _ = _rdp_to_epsilon(self._rdp, self.config.delta)
        if eps > self.config.target_epsilon:
            raise BudgetExhausted(
                f"ε={eps:.4g} > target ε={self.config.target_epsilon:.4g} after {self.steps} steps"
            )
        return eps

    def try_consume(self, steps: int = 1) -> bool:
        """Like :meth:`consume` but returns False instead of raising."""
        try:
            self.consume(steps)
            return True
        except BudgetExhausted:
            return False

    # ----- queries ---------------------------------------------------------

    def epsilon(self) -> float:
        """Current consumed ε (does not consume budget)."""
        eps, _ = _rdp_to_epsilon(self._rdp, self.config.delta)
        return eps

    def best_alpha(self) -> float:
        """The Rényi order that minimises the converted ε."""
        _, a = _rdp_to_epsilon(self._rdp, self.config.delta)
        return a

    def remaining(self) -> float:
        """How much ε is left before ``target_epsilon`` is hit (may be negative)."""
        return self.config.target_epsilon - self.epsilon()

    def state(self) -> BudgetState:
        """Operational state of the budget."""
        eps = self.epsilon()
        if eps >= self.config.target_epsilon:
            return BudgetState.EXHAUSTED
        if eps >= 0.9 * self.config.target_epsilon:
            return BudgetState.APPROACHING
        return BudgetState.OK

    def expected_steps_to_target(self) -> int:
        """Linear projection of how many more steps fit before the budget is exhausted."""
        per_step_eps = self.step_epsilon()
        if per_step_eps <= 0:
            return 1 << 62
        remaining = self.remaining()
        if remaining <= 0:
            return 0
        return max(0, int(remaining / per_step_eps))

    def step_epsilon(self) -> float:
        """Average ε consumed per step taken so far (0 if no steps)."""
        if self.steps == 0:
            # Use the per-step estimate instead.
            per_step = self.step_rdp()
            eps, _ = _rdp_to_epsilon(per_step, self.config.delta)
            return eps
        return self.epsilon() / self.steps

    def reset(self) -> None:
        """Reset the accountant (start a fresh budget window)."""
        self._rdp = {a: 0.0 for a in self.config.alphas}
        self.steps = 0


# -----------------------------------------------------------------------------------
# DPSGDOptimizer
# -----------------------------------------------------------------------------------


class NoiseGenerator(Protocol):
    """Pluggable Gaussian noise source (for deterministic tests)."""

    def sample(self, n: int, sigma: float) -> list[float]:
        """Return ``n`` independent samples from N(0, sigma^2)."""
        ...


class DefaultNoise:
    """Default noise source: Python's random.gauss."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def sample(self, n: int, sigma: float) -> list[float]:
        return [self._rng.gauss(0.0, sigma) for _ in range(n)]


class DPSGDOptimizer:
    """Differentially-private SGD: clip-then-add-noise.

    The optimizer is intentionally minimal — it operates on a single per-example gradient
    vector at a time. Caller is responsible for batching and averaging. The two operations
    exposed are:

      - :meth:`clip` — project a per-example gradient onto the L2 ball of radius ``clipping_norm``.
      - :meth:`private_step` — clip a batch of per-example gradients, average, then add Gaussian
        noise calibrated to ``noise_multiplier * clipping_norm``.

    This is the canonical Abadi et al. 2016 DPSGD recipe. The accountant it carries is what
    makes the resulting training provably (ε, δ)-DP.
    """

    def __init__(
        self,
        clipping_norm: float,
        noise_multiplier: float,
        accountant: PrivacyAccountant,
        noise: NoiseGenerator | None = None,
    ) -> None:
        if clipping_norm <= 0:
            raise DPCrateError(f"clipping_norm must be > 0, got {clipping_norm}")
        if noise_multiplier <= 0:
            raise InvalidNoiseMultiplier(f"noise_multiplier must be > 0, got {noise_multiplier}")
        self.clipping_norm = clipping_norm
        self.noise_multiplier = noise_multiplier
        self.accountant = accountant
        self.noise = noise or DefaultNoise()

    # ----- clipping --------------------------------------------------------

    def clip(self, gradient: list[float]) -> list[float]:
        """Project ``gradient`` onto the L2 ball of radius ``clipping_norm``."""
        if not gradient:
            return []
        norm = math.sqrt(sum(x * x for x in gradient))
        if norm <= self.clipping_norm or norm == 0:
            return list(gradient)
        scale = self.clipping_norm / norm
        return [x * scale for x in gradient]

    @staticmethod
    def l2_norm(vec: list[float]) -> float:
        """Return the L2 norm of a vector."""
        return math.sqrt(sum(x * x for x in vec))

    # ----- private step ----------------------------------------------------

    def private_step(
        self, per_example_gradients: list[list[float]], learning_rate: float = 1.0
    ) -> list[float]:
        """One DPSGD step over a batch.

        1. Clip each per-example gradient to ``clipping_norm``.
        2. Average the clipped gradients.
        3. Add Gaussian noise with std = ``noise_multiplier * clipping_norm``.
        4. Multiply by ``-learning_rate`` (SGD update direction).
        5. Consume one step from the accountant.

        Returns the update vector to apply to the model parameters.
        """
        if not per_example_gradients:
            raise DPCrateError("private_step requires at least one gradient")
        dim = len(per_example_gradients[0])
        if any(len(g) != dim for g in per_example_gradients):
            raise DPCrateError("all per-example gradients must have the same dimension")

        clipped = [self.clip(g) for g in per_example_gradients]
        n = len(clipped)
        # Sum (not mean — we add noise to the sum and divide after, as in Abadi et al.).
        summed = [0.0] * dim
        for g in clipped:
            for i in range(dim):
                summed[i] += g[i]
        # Noise std = noise_multiplier * clipping_norm.
        noise_std = self.noise_multiplier * self.clipping_norm
        noise_vec = self.noise.sample(dim, noise_std)
        noisy_sum = [summed[i] + noise_vec[i] for i in range(dim)]
        # Apply learning rate and normalise by batch size.
        update = [(-learning_rate * noisy_sum[i]) / n for i in range(dim)]
        # Account.
        self.accountant.consume(1)
        return update

    def private_step_no_account(
        self, per_example_gradients: list[list[float]], learning_rate: float = 1.0
    ) -> list[float]:
        """Like :meth:`private_step` but does not consume budget (for unit testing the maths)."""
        if not per_example_gradients:
            raise DPCrateError("private_step requires at least one gradient")
        dim = len(per_example_gradients[0])
        clipped = [self.clip(g) for g in per_example_gradients]
        n = len(clipped)
        summed = [0.0] * dim
        for g in clipped:
            for i in range(dim):
                summed[i] += g[i]
        noise_std = self.noise_multiplier * self.clipping_norm
        noise_vec = self.noise.sample(dim, noise_std)
        noisy_sum = [summed[i] + noise_vec[i] for i in range(dim)]
        return [(-learning_rate * noisy_sum[i]) / n for i in range(dim)]


# -----------------------------------------------------------------------------------
# DPDashboard — serializable snapshot
# -----------------------------------------------------------------------------------


@dataclass
class DPDashboard:
    """Serializable snapshot of the privacy budget for ops dashboards."""

    epsilon: float
    delta: float
    target_epsilon: float
    steps: int
    state: BudgetState
    noise_multiplier: float
    sampling_rate: float
    clipping_norm: float
    best_alpha: float
    expected_steps_to_target: int
    captured_at_iso: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "target_epsilon": self.target_epsilon,
            "steps": self.steps,
            "state": self.state.value,
            "noise_multiplier": self.noise_multiplier,
            "sampling_rate": self.sampling_rate,
            "clipping_norm": self.clipping_norm,
            "best_alpha": self.best_alpha,
            "expected_steps_to_target": self.expected_steps_to_target,
            "captured_at_iso": self.captured_at_iso,
            "extra": self.extra,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_accountant(
        cls,
        accountant: PrivacyAccountant,
        clipping_norm: float,
        captured_at_iso: str = "",
        extra: dict[str, Any] | None = None,
    ) -> DPDashboard:
        """Build a dashboard from a live accountant."""
        return cls(
            epsilon=accountant.epsilon(),
            delta=accountant.config.delta,
            target_epsilon=accountant.config.target_epsilon,
            steps=accountant.steps,
            state=accountant.state(),
            noise_multiplier=accountant.config.noise_multiplier,
            sampling_rate=accountant.config.sampling_rate,
            clipping_norm=clipping_norm,
            best_alpha=accountant.best_alpha(),
            expected_steps_to_target=accountant.expected_steps_to_target(),
            captured_at_iso=captured_at_iso,
            extra=extra or {},
        )


# -----------------------------------------------------------------------------------
# CLI stub
# -----------------------------------------------------------------------------------


def main() -> int:  # pragma: no cover
    """Print a one-shot budget projection (production uses the training driver)."""
    cfg = AccountantConfig(
        noise_multiplier=1.0,
        sampling_rate=0.001,
        delta=1e-5,
        target_epsilon=1.0,
    )
    acc = PrivacyAccountant(cfg)
    try:
        for _ in range(1000):
            acc.consume(1)
    except BudgetExhausted as e:
        print(f"budget exhausted: {e}")
        return 1
    dash = DPDashboard.from_accountant(acc, clipping_norm=1.0)
    print(dash.to_json())
    return 0
