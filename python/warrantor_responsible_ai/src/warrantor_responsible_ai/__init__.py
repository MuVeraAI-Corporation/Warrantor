"""RA1 Responsible-AI — Python verify path for signed RA blocks."""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["RaError", "canonical_block", "verify_ra_block"]


class RaError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonicalize(x) for x in obj]
    return obj


def canonical_block(block: dict[str, Any], action_id: str) -> str:
    combined = {"block": block, "action_id": action_id}
    return json.dumps(_canonicalize(combined), separators=(",", ":"), ensure_ascii=False)


def verify_ra_block(signed: dict[str, Any]) -> None:
    block = signed.get("block")
    if not isinstance(block, dict):
        raise RaError("MALFORMED", "signed RA block missing 'block'")
    action_id = signed.get("action_id", "")
    pub_hex = signed.get("signature_public_key", "")
    sig_hex = signed.get("signature_value", "")
    try:
        pub_bytes = bytes.fromhex(pub_hex)
    except ValueError as e:
        raise RaError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
    if len(pub_bytes) != 32:
        raise RaError("SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as e:
        raise RaError("SIGNATURE_ENVELOPE", f"signature: {e}") from e
    if len(sig_bytes) != 64:
        raise RaError("SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}")
    canonical = canonical_block(block, action_id).encode("utf-8")
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, canonical)
    except (InvalidSignature, ValueError) as e:
        if isinstance(e, InvalidSignature):
            raise RaError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from e
        raise RaError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
