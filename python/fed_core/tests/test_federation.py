"""Tests for aumos-fed-core (F1)."""

from __future__ import annotations

import pytest

from fed_core import (
    DefaultVerifier,
    DPConfig,
    FedAvg,
    Federation,
    ModelUpdate,
    Participant,
    RejectReason,
    Role,
    RoundPhase,
    TeeAttestation,
    _short_hex,  # internal helper reused for nonce-bound signatures
)

# ----- helpers -------------------------------------------------------------------------


def make_attestation(
    pid: str = "t1",
    *,
    nonce: str | None = None,
    expires: str = "2099-01-01T00:00:00Z",
    image: str = "sha256:trusted",
    measurement: str = "meas-A",
) -> TeeAttestation:
    nonce = nonce or "roundnonce"
    sig = "ff" * 16 + _short_hex(f"{pid}|{measurement}|{nonce}".encode())
    return TeeAttestation(
        participant_id=pid,
        tee_kind="sev-snp",
        tee_measurement=measurement,
        client_image_digest=image,
        issued_at="2026-01-01T00:00:00Z",
        expires_at=expires,
        signature_hex=sig,
    )


def make_participant(pid: str = "t1", **kw) -> Participant:
    return Participant(pid, Role.TRAINER, f"pk-{pid}", make_attestation(pid, **kw))


def fixed_nonce_federation(*args, **kw) -> Federation:
    """Build a Federation whose nonce is deterministic so attestations can be pre-bound."""
    fed = Federation(*args, **kw)
    fed.new_nonce = lambda: "roundnonce"  # type: ignore[method-assign]
    return fed


# ----- TeeAttestation ------------------------------------------------------------------


def test_attestation_covers_nonce():
    att = make_attestation("t1", nonce="abc")
    assert att.covers_nonce("abc")
    assert not att.covers_nonce("xyz")


def test_attestation_expired():
    past = make_attestation(expires="2020-01-01T00:00:00Z")
    assert past.is_expired(now_iso="2026-01-01T00:00:00Z")


def test_attestation_not_expired():
    fut = make_attestation(expires="2099-01-01T00:00:00Z")
    assert not fut.is_expired(now_iso="2026-01-01T00:00:00Z")


# ----- FedAvg --------------------------------------------------------------------------


def test_fedavg_weighted_by_num_examples():
    avg = FedAvg()
    out = avg.aggregate(
        [
            ModelUpdate("a", [0.0, 10.0], num_examples=10, loss=0.1),
            ModelUpdate("b", [0.0, 20.0], num_examples=30, loss=0.1),
        ]
    )
    # Weighted: (10*10 + 30*20)/40 = 17.5
    assert out[1] == pytest.approx(17.5)


def test_fedavg_empty_returns_empty():
    assert FedAvg().aggregate([]) == []


def test_fedavg_uniform_when_zero_examples():
    out = FedAvg().aggregate(
        [
            ModelUpdate("a", [0.0, 4.0], num_examples=0, loss=0.1),
            ModelUpdate("b", [0.0, 8.0], num_examples=0, loss=0.1),
        ]
    )
    assert out[1] == pytest.approx(6.0)


def test_fedavg_dp_callback_applied():
    class Const:
        def add_noise(self, params):
            return [x + 1.0 for x in params]

    out = FedAvg(dp_callback=Const()).aggregate(
        [ModelUpdate("a", [1.0, 2.0], num_examples=1, loss=0.0)]
    )
    assert out == [2.0, 3.0]


# ----- DefaultVerifier -----------------------------------------------------------------


def test_verifier_rejects_nan():
    v = DefaultVerifier()
    fed = fixed_nonce_federation("x", verifier=v, initial_parameters=[0.0], min_participants=1)
    p = make_participant()
    fed.register(p)
    res = fed.run_round(updates=[ModelUpdate("t1", [float("nan")], 1, 0.1)])
    assert res.phase == RoundPhase.REJECTED
    assert any(r.reason == RejectReason.UPDATE_NAN_INF for r in res.rejected)


def test_verifier_rejects_inf():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(make_participant())
    res = fed.run_round(updates=[ModelUpdate("t1", [float("inf")], 1, 0.1)])
    assert res.phase == RoundPhase.REJECTED


def test_verifier_rejects_too_large_norm():
    fed = fixed_nonce_federation(
        "x",
        verifier=DefaultVerifier(max_norm=1.0),
        initial_parameters=[0.0],
        min_participants=1,
    )
    fed.register(make_participant())
    res = fed.run_round(updates=[ModelUpdate("t1", [10.0, 10.0], 1, 0.1)])
    assert any(r.reason == RejectReason.UPDATE_TOO_LARGE for r in res.rejected)


def test_verifier_rejects_free_rider():
    fed = fixed_nonce_federation(
        "x",
        verifier=DefaultVerifier(min_delta=0.001),
        initial_parameters=[0.0],
        min_participants=1,
    )
    fed.register(make_participant())
    # Tiny update + non-zero data → suspicious.
    res = fed.run_round(updates=[ModelUpdate("t1", [1e-12], 10, 0.1)])
    assert any(r.reason == RejectReason.FREE_RIDER for r in res.rejected)


def test_verifier_rejects_wrong_image_digest():
    fed = fixed_nonce_federation(
        "x",
        verifier=DefaultVerifier(trusted_client_image_digest="sha256:trusted"),
        initial_parameters=[0.0],
        min_participants=1,
    )
    bad = Participant(
        "t1",
        Role.TRAINER,
        "pk",
        make_attestation(image="sha256:untrusted"),
    )
    fed.register(bad)
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0], 5, 0.1)])
    assert any(r.reason == RejectReason.MEASUREMENT_MISMATCH for r in res.rejected)


# ----- Federation orchestration --------------------------------------------------------


def test_round_succeeds_with_min_participants():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0, 0.0], min_participants=2)
    fed.register(make_participant("t1"))
    fed.register(make_participant("t2"))
    res = fed.run_round(
        updates=[
            ModelUpdate("t1", [1.0, 2.0], 10, 0.5),
            ModelUpdate("t2", [3.0, 4.0], 10, 0.5),
        ]
    )
    assert res.phase == RoundPhase.COMPLETE
    assert res.verification_passed
    assert sorted(res.accepted_participants) == ["t1", "t2"]
    # (1+3)/2, (2+4)/2
    assert res.aggregated_parameters == [2.0, 3.0]


def test_round_rejected_below_quorum():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=2)
    fed.register(make_participant("t1"))
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0], 10, 0.5)])
    assert res.phase == RoundPhase.REJECTED
    assert res.aggregated_parameters is None


def test_unattested_participant_rejected():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(Participant("t1", Role.TRAINER, "pk", None))
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0], 10, 0.5)])
    assert any(r.reason == RejectReason.NO_ATTESTATION for r in res.rejected)
    assert res.phase == RoundPhase.REJECTED


def test_stale_attestation_rejected():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(make_participant(expires="2020-01-01T00:00:00Z"))
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0], 10, 0.5)])
    assert any(r.reason == RejectReason.ATTESTATION_STALE for r in res.rejected)


def test_local_train_callback_invoked():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(make_participant())
    seen: list[str] = []

    def train(pid: str, params: list[float]) -> ModelUpdate:
        seen.append(pid)
        return ModelUpdate(pid, [p + 1.0 for p in params], 5, 0.1)

    res = fed.run_round(local_train=train)
    assert res.phase == RoundPhase.COMPLETE
    assert seen == ["t1"]
    assert fed.global_parameters == [1.0]


def test_duplicate_participant_in_round_rejected():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(make_participant("t1"))
    res = fed.run_round(
        updates=[
            ModelUpdate("t1", [1.0], 10, 0.1),
            ModelUpdate("t1", [2.0], 10, 0.1),  # duplicate
        ]
    )
    assert any(r.reason == RejectReason.DUPLICATE_PARTICIPANT for r in res.rejected)


def test_register_duplicate_returns_error():
    fed = Federation("x")
    fed.register(make_participant("t1"))
    reason = fed.register(make_participant("t1"))
    assert reason == RejectReason.DUPLICATE_PARTICIPANT


def test_deregister_removes_participant():
    fed = Federation("x")
    fed.register(make_participant("t1"))
    assert fed.deregister("t1")
    assert "t1" not in fed.participants
    assert not fed.deregister("t1")


def test_aggregate_failure_rejects_round():
    """If the verifier rejects the aggregate, the round is REJECTED with the aggregate stored."""

    class AngryAgg:
        def aggregate(self, updates):
            return [float("inf")]  # poison aggregate

    fed = fixed_nonce_federation(
        "x",
        aggregator=AngryAgg(),
        initial_parameters=[0.0],
        min_participants=1,
    )
    fed.register(make_participant())
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0], 10, 0.1)])
    assert res.phase == RoundPhase.REJECTED
    assert not res.verification_passed
    # Aggregate is still surfaced for audit.
    assert res.aggregated_parameters == [float("inf")]


def test_round_results_appended_to_history():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(make_participant())
    fed.run_round(updates=[ModelUpdate("t1", [1.0], 1, 0.1)])
    fed.run_round(updates=[ModelUpdate("t1", [2.0], 1, 0.1)])
    assert len(fed.rounds) == 2
    assert fed.rounds[0].round_id == 0
    assert fed.rounds[1].round_id == 1


def test_max_rounds_raises():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1, max_rounds=1)
    fed.register(make_participant())
    fed.run_round(updates=[ModelUpdate("t1", [1.0], 1, 0.1)])
    with pytest.raises(RuntimeError):
        fed.run_round(updates=[ModelUpdate("t1", [1.0], 1, 0.1)])


def test_global_parameters_evolve():
    """Global parameters track the latest aggregate (FedAvg with one trainer returns its update)."""
    fed = fixed_nonce_federation("x", initial_parameters=[0.0, 0.0], min_participants=1)
    fed.register(make_participant())
    fed.run_round(updates=[ModelUpdate("t1", [2.0, 4.0], 1, 0.1)])
    assert fed.global_parameters == [2.0, 4.0]
    fed.run_round(updates=[ModelUpdate("t1", [5.0, 7.0], 1, 0.1)])
    assert fed.global_parameters == [5.0, 7.0]


def test_new_nonce_is_unique():
    fed = Federation("x")
    nonces = {fed.new_nonce() for _ in range(50)}
    assert len(nonces) == 50  # collisions would be catastrophic


def test_round_result_to_dict_serializable():
    fed = fixed_nonce_federation("x", initial_parameters=[0.0], min_participants=1)
    fed.register(make_participant())
    res = fed.run_round(updates=[ModelUpdate("t1", [1.0], 1, 0.1)])
    d = res.to_dict()
    assert d["phase"] == "complete"
    assert d["round_id"] == 0
    assert d["aggregated_digest"].startswith("sha256:")


def test_dp_config_to_dict():
    cfg = DPConfig(
        target_epsilon=1.0,
        target_delta=1e-5,
        clipping_norm=1.0,
        noise_multiplier=0.9,
        num_rounds=100,
    )
    d = cfg.to_dict()
    assert d["target_epsilon"] == 1.0
    assert d["num_rounds"] == 100


def test_model_update_digest_computed():
    u = ModelUpdate("t1", [1.0, 2.0], 5, 0.1)
    assert u.update_digest.startswith("sha256:")
    # Two updates with same data have same digest.
    u2 = ModelUpdate("t1", [1.0, 2.0], 5, 0.1)
    assert u.update_digest == u2.update_digest


def test_model_update_norm_computed():
    u = ModelUpdate("t1", [3.0, 4.0], 5, 0.1)
    assert u.norm == pytest.approx(5.0)


def test_admitted_participants_excludes_unattested():
    fed = fixed_nonce_federation("x")
    fed.register(make_participant("ok"))
    fed.register(Participant("bad", Role.TRAINER, "pk", None))
    admitted = fed.admitted_participants(fed.new_nonce())
    assert [p.participant_id for p in admitted] == ["ok"]


def test_role_filter_in_admitted_participants():
    """Non-trainer roles are never admitted to a training round."""
    fed = fixed_nonce_federation("x")
    fed.register(Participant("agg", Role.AGGREGATOR, "pk", make_attestation("agg")))
    admitted = fed.admitted_participants(fed.new_nonce())
    assert admitted == []


def test_main_returns_zero_on_success():
    from fed_core import main

    assert main() == 0


def test_verifier_check_aggregate_rejects_nan():
    v = DefaultVerifier()
    from fed_core import RoundContext

    ctx = RoundContext(round_id=0, nonce="n")
    assert not v.check_aggregate([float("nan")], [], ctx)


def test_verifier_check_aggregate_rejects_empty():
    v = DefaultVerifier()
    from fed_core import RoundContext

    ctx = RoundContext(round_id=0, nonce="n")
    assert not v.check_aggregate([], [], ctx)
