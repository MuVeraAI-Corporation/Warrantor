

# ---------------------------------------------------------------------------
# AX-27 regression: a real attestation backend must never verify without a
# real verifier. Previously `_verify_envelope` returned
# `bool(measurement) and bool(quote)` for every non-mock backend, and
# `_collect_attestation` fabricated both strings itself -- so asking for
# nvidia-cc handed you verified=True over a quote this process invented.
# ---------------------------------------------------------------------------
import pytest

from aumos_vllm import (
    AttestationEnvelope,
    AttestationUnavailable,
    AttestedVLLMServer,
    HealthStatus,
)


class _StubCollector:
    """A deliberately explicit stand-in for a real platform verifier."""

    def __init__(self, *, honest: bool = True, backend: str = "nvidia-cc") -> None:
        self.honest = honest
        self.backend = backend

    def collect(self, model_path: str, nonce: str) -> AttestationEnvelope:
        return AttestationEnvelope(
            model_path=model_path,
            quote=f"real-quote-bytes:{nonce}",
            report_data=nonce,
            measurement="mrtd:abcdef",
            produced_at=0.0,
            backend=self.backend,
            digest="sha256:" + "0" * 64,
        )

    def verify(self, envelope: AttestationEnvelope) -> bool:
        return self.honest


@pytest.mark.parametrize("backend", ["nvidia-cc", "sev-snp", "tdx"])
def test_real_backend_without_collector_fails_closed(backend: str) -> None:
    """The core AX-27 regression: no verifier => refuse to start, never verified=True."""
    server = AttestedVLLMServer(mode="mock", attestation_backend=backend)
    with pytest.raises(AttestationUnavailable, match="requires a QuoteCollector"):
        server.start("/models/llama-3", gpu_attestation_required=True)


def test_real_backend_with_collector_verifies() -> None:
    server = AttestedVLLMServer(
        mode="mock", attestation_backend="nvidia-cc", quote_collector=_StubCollector()
    )
    server.start("/models/llama-3", gpu_attestation_required=True)
    try:
        env = server.get_attestation_envelope()
        assert env.verified is True
        assert env.backend == "nvidia-cc"
        assert server.health_check() is HealthStatus.HEALTHY
    finally:
        server.stop()


def test_collector_rejection_fails_closed() -> None:
    """A verifier that says no must stop the server, not downgrade to unverified."""
    server = AttestedVLLMServer(
        mode="mock",
        attestation_backend="nvidia-cc",
        quote_collector=_StubCollector(honest=False),
    )
    with pytest.raises(AttestationUnavailable, match="rejected"):
        server.start("/models/llama-3", gpu_attestation_required=True)


def test_collector_backend_mismatch_rejected() -> None:
    """A collector answering for a different platform is not acceptable evidence."""
    server = AttestedVLLMServer(
        mode="mock",
        attestation_backend="tdx",
        quote_collector=_StubCollector(backend="nvidia-cc"),
    )
    with pytest.raises(AttestationUnavailable, match="configured for"):
        server.start("/models/llama-3", gpu_attestation_required=True)


def test_replayed_quote_rejected() -> None:
    """A quote not bound to this instance's nonce is a replay."""

    class _ReplayCollector(_StubCollector):
        def collect(self, model_path: str, nonce: str) -> AttestationEnvelope:
            env = super().collect(model_path, nonce)
            env.report_data = "nonce-from-a-different-instance"
            return env

    server = AttestedVLLMServer(
        mode="mock", attestation_backend="nvidia-cc", quote_collector=_ReplayCollector()
    )
    with pytest.raises(AttestationUnavailable, match="replayed"):
        server.start("/models/llama-3", gpu_attestation_required=True)


def test_mock_backend_still_works_and_is_labelled() -> None:
    """Mock remains usable for local dev -- and is honestly labelled as mock."""
    server = AttestedVLLMServer(mode="mock", attestation_backend="mock")
    server.start("/models/llama-3")
    try:
        env = server.get_attestation_envelope()
        assert env.backend == "mock"
        assert env.verified is True  # digest self-consistency only, not hardware
    finally:
        server.stop()
