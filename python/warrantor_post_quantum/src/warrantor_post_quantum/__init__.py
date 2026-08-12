"""DU1 Post-quantum durability — Python verify path for dual-signed payloads."""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["DuError", "canonical_json", "verify_classical"]


class DuError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonicalize(x) for x in obj]
    return obj


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(_canonicalize(payload), separators=(",", ":"), ensure_ascii=False)


def verify_classical(dual_payload: dict[str, Any]) -> None:
    """Verify the Ed25519 (classical) signature on a dual-signed payload."""
    payload = dual_payload.get("payload")
    classical = dual_payload.get("classical")
    if not isinstance(payload, dict) or not isinstance(classical, dict):
        raise DuError("MALFORMED", "dual payload missing 'payload' or 'classical'")
    pub_hex = classical.get("public_key_hex", "")
    sig_hex = classical.get("signature_hex", "")
    try:
        pub_bytes = bytes.fromhex(pub_hex)
    except ValueError as e:
        raise DuError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
    if len(pub_bytes) != 32:
        raise DuError("SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}")
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as e:
        raise DuError("SIGNATURE_ENVELOPE", f"signature: {e}") from e
    if len(sig_bytes) != 64:
        raise DuError("SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}")
    canonical = canonical_json(payload).encode("utf-8")
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, canonical)
    except (InvalidSignature, ValueError) as e:
        if isinstance(e, InvalidSignature):
            raise DuError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from e
        raise DuError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
