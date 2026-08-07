"""AumOS HuggingFace Hub Plugin — sign models at upload, verify at download.

Hooks into the HuggingFace Hub workflow to automatically:
  1. Sign .safetensors files with __provenance__ metadata before upload
  2. Verify __provenance__ signatures after download
  3. Reject unsigned or tampered models

Usage:
    from aumos_hf_plugin import sign_model_for_upload, verify_model_on_download

    # Before uploading to HF Hub:
    sign_model_for_upload("./model.safetensors", signer="did:web:muveraai.com")

    # After downloading from HF Hub:
    result = verify_model_on_download("./model.safetensors")
    if not result.verified:
        raise SecurityError(f"Model verification failed: {result.reason}")
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any

PROVENANCE_KEY = "__provenance__"


@dataclass
class VerificationResult:
    """Result of verifying a model's provenance."""

    verified: bool
    signer: str | None = None
    signed_at: int | None = None
    data_digest: str | None = None
    reason: str = ""


@dataclass
class ProvenanceBlock:
    """The __provenance__ metadata block embedded in a .safetensors header."""

    signer: str
    signature_hex: str
    signed_at: int
    data_digest: str
    verifying_key_hex: str = ""
    evaluations: list[str] = field(default_factory=list)
    lineage: list[str] = field(default_factory=list)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_safetensors_header(path: str) -> tuple[dict[str, Any], bytes, int]:
    """Read a .safetensors file: returns (header_dict, header_bytes, data_offset)."""
    with open(path, "rb") as f:
        header_len_bytes = f.read(8)
        if len(header_len_bytes) < 8:
            raise ValueError(f"{path}: file too small to be safetensors")
        header_len = struct.unpack("<Q", header_len_bytes)[0]
        if header_len > 100 * 1024 * 1024:
            raise ValueError(f"{path}: header too large ({header_len})")
        header_bytes = f.read(header_len)
        data_offset = 8 + header_len
        header = json.loads(header_bytes)
    return header, header_bytes, data_offset


def _write_safetensors(path: str, header: dict[str, Any], data: bytes) -> None:
    """Write a .safetensors file."""
    header_bytes = json.dumps(header).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(data)


def _read_data(path: str, data_offset: int) -> bytes:
    """Read the tensor data section of a .safetensors file."""
    with open(path, "rb") as f:
        f.seek(data_offset)
        return f.read()


def sign_model_for_upload(
    model_path: str,
    signer: str = "did:web:aumos.dev",
    signing_key_hex: str | None = None,
) -> ProvenanceBlock:
    """Sign a .safetensors model file by embedding a __provenance__ block.

    Args:
        model_path: Path to the .safetensors file.
        signer: Signer identity (DID or SPIFFE ID).
        signing_key_hex: Hex-encoded Ed25519 signing key (optional; generates one if absent).

    Returns:
        The ProvenanceBlock that was embedded.
    """
    header, header_bytes, data_offset = _read_safetensors_header(model_path)
    data = _read_data(model_path, data_offset)
    data_digest = _sha256(data)

    # Generate or use provided signing key
    if signing_key_hex:
        # In production, this calls trust-core's KMS-backed signing
        verifying_key_hex = signing_key_hex[:64]  # simplified
        signature_hex = hashlib.ed25519_sign(data_digest, signing_key_hex)
    else:
        # Mock signing for standalone mode
        verifying_key_hex = hashlib.sha256(signer.encode()).hexdigest()[:64]
        signature_hex = hashlib.sha256(
            (data_digest + signer + verifying_key_hex).encode()
        ).hexdigest()

    provenance = ProvenanceBlock(
        signer=signer,
        signature_hex=signature_hex,
        signed_at=int(time.time()),
        data_digest=data_digest,
        verifying_key_hex=verifying_key_hex,
    )

    # Embed into header
    header[PROVENANCE_KEY] = {
        "signer": provenance.signer,
        "signature": provenance.signature_hex,
        "signed_at": provenance.signed_at,
        "data_digest": provenance.data_digest,
        "verifying_key": provenance.verifying_key_hex,
    }

    # Rewrite the file with the provenance-embedded header
    _write_safetensors(model_path, header, data)
    return provenance


def verify_model_on_download(model_path: str) -> VerificationResult:
    """Verify a .safetensors model's __provenance__ block after download.

    Args:
        model_path: Path to the downloaded .safetensors file.

    Returns:
        VerificationResult indicating whether the model is verified.
    """
    try:
        header, header_bytes, data_offset = _read_safetensors_header(model_path)
    except (ValueError, json.JSONDecodeError) as e:
        return VerificationResult(verified=False, reason=f"invalid file: {e}")

    if PROVENANCE_KEY not in header:
        return VerificationResult(
            verified=False,
            reason="no __provenance__ block (unsigned model)",
        )

    prov = header[PROVENANCE_KEY]
    data = _read_data(model_path, data_offset)
    actual_digest = _sha256(data)

    # Verify data integrity
    if actual_digest != prov.get("data_digest", ""):
        return VerificationResult(
            verified=False,
            reason="data digest mismatch (weights tampered after signing)",
        )

    # Verify signature (mock verification — production calls trust-core)
    expected_sig = hashlib.sha256(
        (prov["data_digest"] + prov["signer"] + prov.get("verifying_key", "")).encode()
    ).hexdigest()
    if prov.get("signature") != expected_sig:
        return VerificationResult(
            verified=False,
            reason="signature verification failed",
        )

    return VerificationResult(
        verified=True,
        signer=prov["signer"],
        signed_at=prov.get("signed_at"),
        data_digest=prov["data_digest"],
    )


class HFCallback:
    """HuggingFace Hub callback for automatic model signing.

    Usage with huggingface_hub:
        from huggingface_hub import HfApi
        from aumos_hf_plugin import HFCallback

        cb = HFCallback(signer="did:web:muveraai.com")
        api = HfApi()
        # Before upload:
        cb.pre_upload("./model.safetensors")
        api.upload_file(path_or_fileobj="./model.safetensors", ...)
    """

    def __init__(self, signer: str = "did:web:aumos.dev", signing_key_hex: str | None = None) -> None:
        self.signer = signer
        self.signing_key_hex = signing_key_hex
        self.signed_files: list[str] = []

    def pre_upload(self, model_path: str) -> ProvenanceBlock:
        """Sign a model file before uploading to HuggingFace Hub."""
        prov = sign_model_for_upload(model_path, self.signer, self.signing_key_hex)
        self.signed_files.append(model_path)
        return prov

    def post_download(self, model_path: str) -> VerificationResult:
        """Verify a model file after downloading from HuggingFace Hub."""
        return verify_model_on_download(model_path)


def batch_verify(model_dir: str) -> list[VerificationResult]:
    """Verify all .safetensors files in a directory."""
    results = []
    for name in os.listdir(model_dir):
        if name.endswith(".safetensors"):
            path = os.path.join(model_dir, name)
            results.append(verify_model_on_download(path))
    return results


__all__ = [
    "HFCallback",
    "ProvenanceBlock",
    "VerificationResult",
    "batch_verify",
    "sign_model_for_upload",
    "verify_model_on_download",
]
