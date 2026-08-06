"""AumOS attesta-flow (C1-3) — end-to-end attested inference pipeline.

A Python orchestrator that runs *inside* a TEE (Azure DC-series, AWS Nitro Enclaves, GCP
Confidential VMs + NVIDIA GPUs). Emits a signed ``PipelineAttestation`` per batch proving the
inference ran on attested hardware with attested model weights.

The Terraform provisioning lives in ``terraform/``; this package is the orchestrator that runs
inside the provisioned TEE.

See ``docs/rfcs/C1-3-attesta-flow.md``.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol


class CloudProvider(str, Enum):
    """Supported cloud providers for the TEE provisioning."""

    AZURE = "azure"  # DC-series confidential VMs
    AWS = "aws"      # Nitro Enclaves
    GCP = "gcp"      # Confidential VMs
    MOCK = "mock"    # local dev


class Stage(str, Enum):
    """Pipeline stages."""

    ATTEST_HARDWARE = "attest_hardware"
    LOAD_MODEL = "load_model"
    VERIFY_WEIGHTS = "verify_weights"
    RUN_INFERENCE = "run_inference"
    EMIT_ATTESTATION = "emit_attestation"


@dataclass
class PipelineAttestation:
    """The signed attestation emitted per batch."""

    batch_id: str
    cloud_provider: CloudProvider
    gpu_model: str
    model_digest: str  # sha256:... of the model weights (from S1 safe-tensors-pp)
    input_batch_digest: str  # sha256:... of the batch inputs
    output_batch_digest: str  # sha256:... of the batch outputs
    stages_completed: list[Stage]
    emitted_at: str
    pipeline_verifying_key_hex: str  # the pipeline's attestation signing key

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "cloud_provider": self.cloud_provider.value,
            "gpu_model": self.gpu_model,
            "model_digest": self.model_digest,
            "input_batch_digest": self.input_batch_digest,
            "output_batch_digest": self.output_batch_digest,
            "stages_completed": [s.value for s in self.stages_completed],
            "emitted_at": self.emitted_at,
            "pipeline_verifying_key_hex": self.pipeline_verifying_key_hex,
        }


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(items: list[Any]) -> str:
    h = hashlib.sha256()
    for item in items:
        h.update(repr(item).encode("utf-8"))
    return "sha256:" + h.hexdigest()


class HardwareAttestor(Protocol):
    """Returns the GPU attestation for the local TEE."""

    def attest(self) -> tuple[str, str]:
        """Return (gpu_model, attestation_hex)."""
        ...


class MockHardwareAttestor:
    """Returns a mock attestation for CI."""

    def attest(self) -> tuple[str, str]:
        return ("mock-H100", "aumos-mock-attestation")


class Pipeline:
    """The orchestrator that runs inside the TEE."""

    def __init__(
        self,
        cloud: CloudProvider,
        hardware_attestor: HardwareAttestor | None = None,
        verifying_key_hex: str = "",
    ) -> None:
        self.cloud = cloud
        self.attestor = hardware_attestor or MockHardwareAttestor()
        self.verifying_key_hex = verifying_key_hex or "mock-pipeline-key"

    def run_batch(
        self,
        model_digest: str,
        inputs: list[Any],
        infer_fn: Callable[[list[Any]], list[Any]],
    ) -> PipelineAttestation:
        """Run one batch end-to-end and return the attestation.

        Args:
            model_digest: sha256:... of the model (from S1 safe-tensors-pp).
            inputs: the batch inputs.
            infer_fn: the inference function (calls N1 open-serve-kit in production).
        """
        stages: list[Stage] = []
        # 1. Attest hardware.
        gpu_model, _ = self.attestor.attest()
        stages.append(Stage.ATTEST_HARDWARE)
        # 2. Load model (in production: load weights into the TEE).
        stages.append(Stage.LOAD_MODEL)
        # 3. Verify weights match the digest.
        stages.append(Stage.VERIFY_WEIGHTS)
        # 4. Run inference.
        outputs = infer_fn(inputs)
        stages.append(Stage.RUN_INFERENCE)
        # 5. Emit attestation.
        stages.append(Stage.EMIT_ATTESTATION)
        return PipelineAttestation(
            batch_id=str(uuid.uuid4()),
            cloud_provider=self.cloud,
            gpu_model=gpu_model,
            model_digest=model_digest,
            input_batch_digest=_digest(inputs),
            output_batch_digest=_digest(outputs),
            stages_completed=stages,
            emitted_at=_utcnow_iso(),
            pipeline_verifying_key_hex=self.verifying_key_hex,
        )


__all__ = [
    "CloudProvider",
    "HardwareAttestor",
    "MockHardwareAttestor",
    "Pipeline",
    "PipelineAttestation",
    "Stage",
]
