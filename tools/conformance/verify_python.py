#!/usr/bin/env python3
"""A6 conformance — Python verifier entry point.

Reads a golden vector from stdin (JSON) and verifies the signature against the recorded
verifying key using PyNaCl (libsodium Ed25519). Exits 0 on success, 1 on mismatch.

Mirrors the Rust and Go verifiers in this directory; running all three against the same
vector is the cross-language conformance test for T1 trust-core.
"""
from __future__ import annotations

import json
import sys
from typing import Any


def main() -> int:
    raw = sys.stdin.read()
    v: dict[str, Any] = json.loads(raw)

    payload = bytes.fromhex(v["payload_hex"])
    vk_bytes = bytes.fromhex(v["verifying_key_hex"])
    sig = bytes.fromhex(v["signature_hex"])

    try:
        # Prefer PyNaCl; fall back to a pure-python Ed25519 if not available.
        try:
            from nacl.signing import VerifyKey
            from nacl.exceptions import BadSignatureError
            vk = VerifyKey(vk_bytes)
            try:
                vk.verify(payload, sig)
                valid = True
            except BadSignatureError:
                valid = False
        except ImportError:
            # cryptography has Ed25519PublicKey
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            vk = Ed25519PublicKey.from_public_bytes(vk_bytes)
            try:
                vk.verify(sig, payload)
                valid = True
            except InvalidSignature:
                valid = False
    except Exception as e:  # noqa: BLE001
        print(f"python: verifier error: {e}", file=sys.stderr)
        return 2

    expected = v["expected"] == "valid"
    if valid == expected:
        print(f"python: ok (valid={valid}, expected={v['expected']})")
        return 0
    print(f"python: MISMATCH (valid={valid}, expected={v['expected']})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
