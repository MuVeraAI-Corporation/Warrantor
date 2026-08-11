#!/usr/bin/env python3
"""Python batch verifier for the strict cross-language protocol TCK.

Reads ``{"keyring": {...}, "vectors": [...]}`` from stdin and writes one JSON
line of per-vector results, matching the wire contract of
``rust/protocol-contracts/src/bin/protocol_tck.rs``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PYTHON_PACKAGE_SOURCE = REPOSITORY_ROOT / "python" / "protocol_contracts" / "src"

if str(PYTHON_PACKAGE_SOURCE) not in sys.path:
    sys.path.insert(0, str(PYTHON_PACKAGE_SOURCE))

from protocol_contracts.validation import ProtocolValidator  # noqa: E402


def main() -> int:
    """Validate a batch of protocol vectors with the Python reference validator."""

    if len(sys.argv) < 2:
        print("usage: verify_protocol_python.py <registry.json>", file=sys.stderr)
        return 2
    registry_path = Path(sys.argv[1])
    registry = cast(dict[str, object], json.loads(registry_path.read_text(encoding="utf-8")))
    supported_critical_extensions = frozenset(
        cast(list[str], registry.get("supported_critical_extensions", []))
    )
    batch = cast(dict[str, object], json.loads(sys.stdin.read()))
    keyring = {
        key_id: bytes.fromhex(encoded)
        for key_id, encoded in cast(dict[str, str], batch["keyring"]).items()
    }
    validator = ProtocolValidator(
        registry_path.parent,
        keyring,
        supported_critical_extensions,
    )
    results: list[dict[str, object]] = []
    for entry in cast(list[dict[str, object]], batch["vectors"]):
        result = validator.validate(
            entry["document"],
            cast(str, entry["protocol"]),
            cast(int, entry["validation_time"]),
        )
        results.append(
            {
                "id": cast(str, entry["id"]),
                "valid": result.valid,
                "error_code": result.error_code,
                "detail": result.detail,
            }
        )
    print(json.dumps({"implementation": "python", "results": results}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
