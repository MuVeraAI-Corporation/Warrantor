"""Tests for warrantor_hf_plugin: sign, verify, tamper detection, batch, callback."""

from __future__ import annotations

import json
import struct

import pytest

from warrantor_hf_plugin import (
    HFCallback,
    ProvenanceBlock,
    VerificationResult,
    batch_verify,
    sign_model_for_upload,
    verify_model_on_download,
)


def _create_safetensors(path: str, weights: bytes = b"\x00" * 16) -> dict:
    """Create a minimal valid .safetensors file."""
    header = {
        "__metadata__": {"format": "pt"},
        "weight_0": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, len(weights)]},
    }
    header_bytes = json.dumps(header).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(weights)
    return header


def test_sign_embeds_provenance(tmp_path: pytest.TempPathFactory) -> None:
    path = str(tmp_path / "model.safetensors")
    _create_safetensors(path)
    prov = sign_model_for_upload(path, signer="did:web:test.com")
    assert prov.signer == "did:web:test.com"
    assert prov.data_digest.startswith("sha256:")
    # Verify the header now has __provenance__
    with open(path, "rb") as f:
        hlen = struct.unpack("<Q", f.read(8))[0]
        header = json.loads(f.read(hlen))
    assert "__provenance__" in header
    assert header["__provenance__"]["signer"] == "did:web:test.com"


def test_verify_signed_model(tmp_path: pytest.TempPathFactory) -> None:
    path = str(tmp_path / "model.safetensors")
    _create_safetensors(path)
    sign_model_for_upload(path, signer="did:web:test.com")
    result = verify_model_on_download(path)
    assert result.verified
    assert result.signer == "did:web:test.com"


def test_verify_unsigned_model_fails(tmp_path: pytest.TempPathFactory) -> None:
    path = str(tmp_path / "model.safetensors")
    _create_safetensors(path)
    result = verify_model_on_download(path)
    assert not result.verified
    assert "unsigned" in result.reason.lower()


def test_tampered_weights_fail(tmp_path: pytest.TempPathFactory) -> None:
    path = str(tmp_path / "model.safetensors")
    _create_safetensors(path)
    sign_model_for_upload(path, signer="did:web:test.com")
    # Tamper: append extra bytes to the data section
    with open(path, "ab") as f:
        f.write(b"\xff" * 4)
    result = verify_model_on_download(path)
    assert not result.verified
    assert "digest" in result.reason.lower() or "tampered" in result.reason.lower()


def test_callback_pre_upload_signs(tmp_path: pytest.TempPathFactory) -> None:
    path = str(tmp_path / "model.safetensors")
    _create_safetensors(path)
    cb = HFCallback(signer="did:web:cb.com")
    prov = cb.pre_upload(path)
    assert prov.signer == "did:web:cb.com"
    assert path in cb.signed_files


def test_callback_post_download_verifies(tmp_path: pytest.TempPathFactory) -> None:
    path = str(tmp_path / "model.safetensors")
    _create_safetensors(path)
    cb = HFCallback(signer="did:web:cb.com")
    cb.pre_upload(path)
    result = cb.post_download(path)
    assert result.verified


def test_batch_verify_multiple_files(tmp_path: pytest.TempPathFactory) -> None:
    for i in range(3):
        p = str(tmp_path / f"model_{i}.safetensors")
        _create_safetensors(p)
        sign_model_for_upload(p, signer="did:web:batch.com")
    results = batch_verify(str(tmp_path))
    assert len(results) == 3
    assert all(r.verified for r in results)


def test_batch_verify_mixed_signed_unsigned(tmp_path: pytest.TempPathFactory) -> None:
    # Signed
    p1 = str(tmp_path / "signed.safetensors")
    _create_safetensors(p1)
    sign_model_for_upload(p1)
    # Unsigned
    p2 = str(tmp_path / "unsigned.safetensors")
    _create_safetensors(p2)
    results = batch_verify(str(tmp_path))
    assert len(results) == 2
    verified = [r for r in results if r.verified]
    unverified = [r for r in results if not r.verified]
    assert len(verified) == 1
    assert len(unverified) == 1


def test_provenance_block_fields() -> None:
    prov = ProvenanceBlock(
        signer="did:web:test.com",
        signature_hex="abc123",
        signed_at=1000,
        data_digest="sha256:def456",
    )
    assert prov.signer == "did:web:test.com"
    assert prov.evaluations == []
    assert prov.lineage == []


def test_verification_result_dataclass() -> None:
    r = VerificationResult(verified=True, signer="test", signed_at=1000)
    assert r.verified
    assert r.reason == ""
