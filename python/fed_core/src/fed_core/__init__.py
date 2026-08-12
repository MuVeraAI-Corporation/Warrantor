"""Warrantor fed-core (F1) — attested federated training orchestration.

Three roles collaborate:

  - **Aggregator** (the coordinator, runs in a TEE): collects model updates from trainers,
    averages them with :class:`FedAvg`, runs the verifier over the aggregated delta, then
    publishes the new global model. Refuses to admit a trainer that does not present a valid
    TEE attestation bound to the round nonce.
  - **Trainer** (one per participant): runs local training (PyTorch, NeMo, JAX — abstracted by
    the :class:`TrainingEngine` protocol), then emits a signed update plus its measurement.
  - **Verifier** (a small, stateless checker): rejects updates with NaN/Inf, with too-large
    norms (poisoning / free-rider defence), or whose measurement diverges from the trusted
    client image. The verifier is intentionally dumb so it can run in a separate enclave.

Differential privacy is delegated to F2 ``dp-crate``; this package only calls into it via
:class:`DPConfig` / :class:`DPNoiseCallback` to avoid a hard runtime dependency (the protocol
shape matches F2's public API).

See ``docs/rfcs/F1-fed-core.md``.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol

# -----------------------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------------------


class Role(str, Enum):
    """The three federation roles."""

    AGGREGATOR = "aggregator"
    TRAINER = "trainer"
    VERIFIER = "verifier"


class RoundPhase(str, Enum):
    """The phases of one federation round."""

    OPEN = "open"
    COLLECT = "collect"
    AGGREGATE = "aggregate"
    VERIFY = "verify"
    PUBLISH = "publish"
    COMPLETE = "complete"
    REJECTED = "rejected"


class RejectReason(str, Enum):
    """Why a participant or update was rejected."""

    NO_ATTESTATION = "no_attestation"
    ATTESTATION_INVALID = "attestation_invalid"
    ATTESTATION_STALE = "attestation_stale"
    WRONG_ROUND = "wrong_round"
    WRONG_NONCE = "wrong_nonce"
    UPDATE_NAN_INF = "update_nan_inf"
    UPDATE_TOO_LARGE = "update_too_large"
    FREE_RIDER = "free_rider"
    MEASUREMENT_MISMATCH = "measurement_mismatch"
    DUPLICATE_PARTICIPANT = "duplicate_participant"


# -----------------------------------------------------------------------------------
# Dataclasses
# -----------------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(items: list[Any]) -> str:
    h = hashlib.sha256()
    for item in items:
        h.update(repr(item).encode("utf-8"))
    return "sha256:" + h.hexdigest()


@dataclass
class TeeAttestation:
    """The attestation each participant must present to join a round.

    In production this is a C1-3 attesta-flow ``PipelineAttestation``; the fields here are the
    subset the aggregator needs to make an admit/deny decision.
    """

    participant_id: str
    tee_kind: str  # "sev-snp", "tdx", "nitro", "az-snp-cvm", "mock"
    tee_measurement: str
    client_image_digest: str  # sha256:... of the trusted training client image
    issued_at: str  # RFC-3339
    expires_at: str  # RFC-3339
    signature_hex: str  # signature over (participant_id | tee_measurement | nonce)

    def covers_nonce(self, nonce: str) -> bool:
        """True if the attestation's signature scope includes the round ``nonce``."""
        # The signing input is a fixed canonical string; the verifier rebuilds it.
        msg = f"{self.participant_id}|{self.tee_measurement}|{nonce}".encode()
        return self.signature_hex.endswith(_short_hex(msg))

    def is_expired(self, now_iso: str | None = None) -> bool:
        """True if ``expires_at`` is before ``now_iso`` (default: now)."""
        now = now_iso or _utcnow_iso()
        return self.expires_at < now


def _short_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


@dataclass
class ModelUpdate:
    """One participant's local training output.

    ``parameters`` is a flat list of floats (so the framework is irrelevant — PyTorch, NeMo,
    JAX all flatten to a vector). ``num_examples`` is the weight used by :class:`FedAvg`.
    """

    participant_id: str
    parameters: list[float]
    num_examples: int
    loss: float
    norm: float = 0.0
    update_digest: str = ""

    def __post_init__(self) -> None:
        if not self.update_digest:
            self.update_digest = _digest(
                [self.participant_id, tuple(self.parameters), self.num_examples]
            )
        if self.norm == 0.0:
            self.norm = math.sqrt(sum(x * x for x in self.parameters))


@dataclass
class RejectedUpdate:
    """A rejected update and the reason."""

    participant_id: str
    reason: RejectReason
    detail: str = ""


@dataclass
class RoundResult:
    """The aggregate outcome of a federation round."""

    round_id: int
    phase: RoundPhase
    accepted_participants: list[str]
    rejected: list[RejectedUpdate]
    aggregated_parameters: list[float] | None
    aggregated_digest: str
    verification_passed: bool
    started_at: str
    ended_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "round_id": self.round_id,
            "phase": self.phase.value,
            "accepted_participants": self.accepted_participants,
            "rejected": [
                {"participant_id": r.participant_id, "reason": r.reason.value, "detail": r.detail}
                for r in self.rejected
            ],
            "aggregated_digest": self.aggregated_digest,
            "verification_passed": self.verification_passed,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }


# -----------------------------------------------------------------------------------
# Pluggable strategies
# -----------------------------------------------------------------------------------


class Aggregator(Protocol):
    """Aggregation strategy (FedAvg, FedProx, FedYogi, ...)."""

    def aggregate(self, updates: list[ModelUpdate]) -> list[float]:
        """Combine accepted updates into a new parameter vector."""
        ...


class Verifier(Protocol):
    """Per-update and post-aggregate verifier."""

    def check_update(self, update: ModelUpdate, ctx: RoundContext) -> RejectedUpdate | None:
        """Return a :class:`RejectedUpdate` if the update fails, else ``None``."""
        ...

    def check_aggregate(
        self, aggregate: list[float], updates: list[ModelUpdate], ctx: RoundContext
    ) -> bool:
        """Return True if the aggregated delta is acceptable."""
        ...


class TrainingEngine(Protocol):
    """The framework-abstract training engine (PyTorch / NeMo / JAX)."""

    def train_local(self, global_parameters: list[float]) -> ModelUpdate:
        """Run one local epoch starting from ``global_parameters``."""
        ...


class DPNoiseCallback(Protocol):
    """Optional DP-noise injection hook (delegated to F2 dp-crate)."""

    def add_noise(self, parameters: list[float]) -> list[float]:
        """Return a noisier copy of ``parameters``."""
        ...


@dataclass
class DPConfig:
    """Configuration handed to F2 dp-crate. Stored for audit; not consumed directly here."""

    target_epsilon: float
    target_delta: float
    clipping_norm: float
    noise_multiplier: float
    num_rounds: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_epsilon": self.target_epsilon,
            "target_delta": self.target_delta,
            "clipping_norm": self.clipping_norm,
            "noise_multiplier": self.noise_multiplier,
            "num_rounds": self.num_rounds,
        }


# -----------------------------------------------------------------------------------
# Concrete strategies
# -----------------------------------------------------------------------------------


class FedAvg:
    """Standard federated averaging: weighted mean by ``num_examples``."""

    def __init__(self, dp_callback: DPNoiseCallback | None = None) -> None:
        self.dp_callback = dp_callback

    def aggregate(self, updates: list[ModelUpdate]) -> list[float]:
        if not updates:
            return []
        total = sum(u.num_examples for u in updates)
        if total == 0:
            # Fall back to uniform weighting if everyone lied about their data size.
            n = len(updates)
            dim = len(updates[0].parameters)
            return [(sum(u.parameters[i] for u in updates) / n) for i in range(dim)]
        dim = len(updates[0].parameters)
        out = [0.0] * dim
        for u in updates:
            w = u.num_examples / total
            for i in range(dim):
                out[i] += w * u.parameters[i]
        if self.dp_callback is not None:
            out = self.dp_callback.add_noise(out)
        return out


class DefaultVerifier:
    """Concrete Verifier: NaN/Inf, norm cap (poisoning), free-rider, measurement match."""

    def __init__(
        self,
        max_norm: float = 1.0e6,
        min_delta: float = 1.0e-9,
        trusted_client_image_digest: str = "",
    ) -> None:
        self.max_norm = max_norm
        self.min_delta = min_delta
        self.trusted_client_image_digest = trusted_client_image_digest

    def check_update(self, update: ModelUpdate, ctx: RoundContext) -> RejectedUpdate | None:
        if not update.parameters:
            return RejectedUpdate(update.participant_id, RejectReason.FREE_RIDER, "empty update")
        if any(math.isnan(x) or math.isinf(x) for x in update.parameters):
            return RejectedUpdate(update.participant_id, RejectReason.UPDATE_NAN_INF)
        if update.norm > self.max_norm:
            return RejectedUpdate(
                update.participant_id,
                RejectReason.UPDATE_TOO_LARGE,
                f"norm {update.norm:.3g} > {self.max_norm:.3g}",
            )
        # Free-rider: a near-zero delta with non-zero data size is suspicious.
        if update.norm < self.min_delta and update.num_examples > 0:
            return RejectedUpdate(update.participant_id, RejectReason.FREE_RIDER)
        # Measurement: ensure the trainer is running the trusted client image.
        att = ctx.attestations.get(update.participant_id)
        if att is None:
            return RejectedUpdate(
                update.participant_id, RejectReason.MEASUREMENT_MISMATCH, "no attestation"
            )
        if (
            self.trusted_client_image_digest
            and att.client_image_digest != self.trusted_client_image_digest
        ):
            return RejectedUpdate(
                update.participant_id,
                RejectReason.MEASUREMENT_MISMATCH,
                f"image {att.client_image_digest} != {self.trusted_client_image_digest}",
            )
        return None

    def check_aggregate(
        self, aggregate: list[float], updates: list[ModelUpdate], ctx: RoundContext
    ) -> bool:
        if not aggregate:
            return False
        if any(math.isnan(x) or math.isinf(x) for x in aggregate):
            return False
        # Aggregate must not exceed the largest contributor norm * len — a basic sanity cap.
        if updates:
            cap = max(u.norm for u in updates) * len(updates) + 1.0
            agg_norm = math.sqrt(sum(x * x for x in aggregate))
            if agg_norm > cap:
                return False
        return True


# -----------------------------------------------------------------------------------
# Participant + Federation
# -----------------------------------------------------------------------------------


@dataclass
class Participant:
    """A federated-learning participant with a role and an attestation."""

    participant_id: str
    role: Role
    public_key_hex: str
    attestation: TeeAttestation | None = None

    def admit_to(self, nonce: str, now_iso: str | None = None) -> RejectReason | None:
        """Return a RejectReason if this participant may NOT join a round, else None."""
        if self.attestation is None:
            return RejectReason.NO_ATTESTATION
        if self.attestation.is_expired(now_iso):
            return RejectReason.ATTESTATION_STALE
        if not self.attestation.covers_nonce(nonce):
            return RejectReason.WRONG_NONCE
        return None


@dataclass
class RoundContext:
    """State shared across the per-update verifier calls in one round."""

    round_id: int
    nonce: str
    attestations: dict[str, TeeAttestation] = field(default_factory=dict)
    accepted: list[str] = field(default_factory=list)
    rejected: list[RejectedUpdate] = field(default_factory=list)
    started_at: str = ""

    def record_attestation(self, att: TeeAttestation) -> None:
        self.attestations[att.participant_id] = att


class Federation:
    """The orchestrator. Holds participants, advances rounds, emits RoundResults.

    The federation is single-process and synchronous — production wraps it in the C1-3
    attesta-flow pipeline (which gives it real TEE attestation, gRPC fan-out, and persistent
    audit). The class itself is intentionally pure-Python and dependency-free.
    """

    def __init__(
        self,
        name: str,
        aggregator: Aggregator | None = None,
        verifier: Verifier | None = None,
        initial_parameters: list[float] | None = None,
        min_participants: int = 2,
        max_rounds: int = 100,
        trusted_client_image_digest: str = "",
    ) -> None:
        self.name = name
        self.aggregator: Aggregator = aggregator or FedAvg()
        self.verifier: Verifier = verifier or DefaultVerifier(
            trusted_client_image_digest=trusted_client_image_digest
        )
        self.global_parameters: list[float] = list(initial_parameters or [])
        self.min_participants = max(1, min_participants)
        self.max_rounds = max(1, max_rounds)
        self.trusted_client_image_digest = trusted_client_image_digest
        self.participants: dict[str, Participant] = {}
        self.rounds: list[RoundResult] = []
        self._next_round_id = 0

    # ----- participant management ------------------------------------------

    def register(self, p: Participant) -> RejectReason | None:
        """Register a participant. Returns a RejectReason on conflict."""
        if p.participant_id in self.participants:
            return RejectReason.DUPLICATE_PARTICIPANT
        self.participants[p.participant_id] = p
        return None

    def deregister(self, participant_id: str) -> bool:
        return self.participants.pop(participant_id, None) is not None

    def admitted_participants(self, nonce: str, now_iso: str | None = None) -> list[Participant]:
        """Return only participants whose attestation covers ``nonce``."""
        out: list[Participant] = []
        for p in self.participants.values():
            if p.role != Role.TRAINER:
                continue
            if p.admit_to(nonce, now_iso) is None:
                out.append(p)
        return out

    # ----- round orchestration ---------------------------------------------

    def new_nonce(self) -> str:
        """Generate a fresh 128-bit round nonce (hex)."""
        return secrets.token_hex(16)

    def run_round(
        self,
        local_train: Callable[[str, list[float]], ModelUpdate] | None = None,
        updates: list[ModelUpdate] | None = None,
    ) -> RoundResult:
        """Run one full round (open → collect → aggregate → verify → publish).

        Either pass ``updates`` directly (the synchronous CI path) or pass ``local_train`` with
        signature ``(participant_id, global_parameters) -> ModelUpdate`` to have the federation
        collect from each admitted participant. ``local_train`` typically delegates to a
        :class:`TrainingEngine` (PyTorch / NeMo).
        """
        started = _utcnow_iso()
        round_id = self._next_round_id
        self._next_round_id += 1
        if round_id >= self.max_rounds:
            raise RuntimeError(f"fed-core: max_rounds ({self.max_rounds}) reached")
        nonce = self.new_nonce()
        ctx = RoundContext(round_id=round_id, nonce=nonce, started_at=started)
        # Pre-load attestations of every admitted participant into the round context.
        admitted = self.admitted_participants(nonce, started)
        for p in admitted:
            assert p.attestation is not None  # admitted implies attested
            ctx.record_attestation(p.attestation)
        # Compute the admit gate once: which participants passed attestation?
        rejected_ids: set[str] = set()
        for p in self.participants.values():
            if p.role != Role.TRAINER:
                continue
            reason = p.admit_to(nonce, started)
            if reason is not None:
                ctx.rejected.append(RejectedUpdate(p.participant_id, reason, "attestation gate"))
                rejected_ids.add(p.participant_id)
        # Collect updates.
        collected: list[ModelUpdate] = []
        if updates is not None:
            collected = list(updates)
        elif local_train is not None:
            for p in admitted:
                collected.append(local_train(p.participant_id, list(self.global_parameters)))
        # Verify per-update.
        verified: list[ModelUpdate] = []
        seen: set[str] = set()
        for u in collected:
            if u.participant_id in seen:
                ctx.rejected.append(
                    RejectedUpdate(u.participant_id, RejectReason.DUPLICATE_PARTICIPANT)
                )
                continue
            seen.add(u.participant_id)
            # Enforce the admit gate: updates from unattested or nonce-mismatched
            # participants are dropped before the per-update verifier even runs.
            if u.participant_id in rejected_ids:
                continue
            # Bind the attestation into the context for the verifier (covers the case where the
            # caller supplied updates directly).
            if u.participant_id not in ctx.attestations:
                pt = self.participants.get(u.participant_id)
                if pt is not None and pt.attestation is not None:
                    ctx.record_attestation(pt.attestation)
            rej = self.verifier.check_update(u, ctx)
            if rej is not None:
                ctx.rejected.append(rej)
            else:
                verified.append(u)
                ctx.accepted.append(u.participant_id)
        # Quorum check.
        if len(verified) < self.min_participants:
            result = RoundResult(
                round_id=round_id,
                phase=RoundPhase.REJECTED,
                accepted_participants=ctx.accepted,
                rejected=ctx.rejected,
                aggregated_parameters=None,
                aggregated_digest="",
                verification_passed=False,
                started_at=started,
                ended_at=_utcnow_iso(),
            )
            self.rounds.append(result)
            return result
        # Aggregate.
        aggregated = self.aggregator.aggregate(verified)
        # Verify aggregate.
        ok = self.verifier.check_aggregate(aggregated, verified, ctx)
        if not ok:
            result = RoundResult(
                round_id=round_id,
                phase=RoundPhase.REJECTED,
                accepted_participants=ctx.accepted,
                rejected=ctx.rejected,
                aggregated_parameters=aggregated,
                aggregated_digest=_digest([tuple(aggregated)]),
                verification_passed=False,
                started_at=started,
                ended_at=_utcnow_iso(),
            )
            self.rounds.append(result)
            return result
        # Publish.
        self.global_parameters = aggregated
        agg_digest = _digest([tuple(aggregated)])
        result = RoundResult(
            round_id=round_id,
            phase=RoundPhase.COMPLETE,
            accepted_participants=ctx.accepted,
            rejected=ctx.rejected,
            aggregated_parameters=aggregated,
            aggregated_digest=agg_digest,
            verification_passed=True,
            started_at=started,
            ended_at=_utcnow_iso(),
        )
        self.rounds.append(result)
        return result


# -----------------------------------------------------------------------------------
# CLI entrypoint stub
# -----------------------------------------------------------------------------------


def main() -> int:  # pragma: no cover
    """Run a tiny self-check (production uses the attesta-flow driver)."""
    fed = Federation("self-check", initial_parameters=[0.0, 0.0], min_participants=1)
    # Pin the nonce so the self-issued attestation covers it.
    nonce = "self-check-nonce"
    fed.new_nonce = lambda: nonce  # type: ignore[method-assign]
    att = TeeAttestation(
        participant_id="t1",
        tee_kind="mock",
        tee_measurement="m",
        client_image_digest="sha256:img",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        signature_hex="x" * 16 + _short_hex(f"t1|m|{nonce}".encode()),
    )
    fed.register(Participant("t1", Role.TRAINER, "pk1", att))
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0, 2.0], 10, 0.5)])
    print(f"round phase = {res.phase.value}")
    return 0 if res.verification_passed else 1
