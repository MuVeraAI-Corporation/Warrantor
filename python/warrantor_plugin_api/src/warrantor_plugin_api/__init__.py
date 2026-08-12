"""X1 Plugin API — Python verify path for signed plugin manifests."""

from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["PluginError", "canonical_manifest", "verify_plugin"]


class PluginError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonicalize(x) for x in obj]
    return obj


def canonical_manifest(manifest: dict[str, Any], artifact_digest: str) -> str:
    combined = {"manifest": manifest, "artifact_digest": artifact_digest}
    return json.dumps(_canonicalize(combined), separators=(",", ":"), ensure_ascii=False)


def verify_plugin(plugin: dict[str, Any]) -> None:
    """Verify a signed plugin's Ed25519 signature over its manifest + artifact digest."""
    manifest = plugin.get("manifest")
    if not isinstance(manifest, dict):
        raise PluginError("MALFORMED", "plugin missing manifest")
    artifact_digest = plugin.get("artifact_digest", "")
    pub_hex = plugin.get("signature_public_key", "")
    sig_hex = plugin.get("signature_value", "")
    try:
        pub_bytes = bytes.fromhex(pub_hex)
    except ValueError as e:
        raise PluginError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
    if len(pub_bytes) != 32:
        raise PluginError(
            "SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}"
        )
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError as e:
        raise PluginError("SIGNATURE_ENVELOPE", f"signature: {e}") from e
    if len(sig_bytes) != 64:
        raise PluginError("SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}")
    canonical = canonical_manifest(manifest, artifact_digest).encode("utf-8")
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, canonical)
    except (InvalidSignature, ValueError) as e:
        if isinstance(e, InvalidSignature):
            raise PluginError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from e
        raise PluginError("SIGNATURE_ENVELOPE", f"public_key: {e}") from e
