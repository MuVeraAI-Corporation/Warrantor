#!/usr/bin/env python3
"""A6 conformance — Python Merkle-root verifier.

Reads a Merkle golden vector from stdin (JSON) and recomputes the RFC 6962 root over
`leaves_hex`, comparing to `expected_root_hex`. Exits 0 on match, 1 on mismatch.

Mirrors the Rust `merkle_vector` example and the Go verifier in this directory; running
all three against the same vector is the cross-language conformance test for the T1
trust-core Merkle primitive.

RFC 6962 ordering: leaf = SHA-256(0x00 || leaf), node = SHA-256(0x01 || left || right),
orphan-promotion for odd layers (no duplication).
"""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    layer = [leaf_hash(l) for l in leaves]
    while len(layer) > 1:
        nxt: list[bytes] = []
        i = 0
        while i < len(layer):
            if i + 1 < len(layer):
                nxt.append(node_hash(layer[i], layer[i + 1]))
            else:
                nxt.append(layer[i])  # orphan promotion
            i += 2
        layer = nxt
    return layer[0]


def main() -> int:
    raw = sys.stdin.read()
    v: dict[str, Any] = json.loads(raw)

    leaves_hex = v["leaves_hex"]
    expected = v["expected_root_hex"]
    leaves = [bytes.fromhex(h) for h in leaves_hex]
    computed = merkle_root(leaves).hex()
    if computed == expected:
        print(f"python: merkle ok (computed={computed})")
        return 0
    print(
        f"python: merkle MISMATCH (computed={computed}, expected={expected})",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
