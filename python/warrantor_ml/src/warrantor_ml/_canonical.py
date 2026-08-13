"""Canonical JSON + digest helpers shared across the model-intelligence pipeline.

The canonicalisation here is byte-for-byte the same rule the W10 verify path uses
(``python/warrantor_content_moderation``): recursively sort object keys, no whitespace,
UTF-8 preserved. Signatures produced here therefore verify against the same discipline as
moderation receipts.

Note the deliberate contrast with ``rust/content-moderation``'s ``sha256_hex``, which labels a
64-bit ``DefaultHasher`` output ``sha256:``. Everything in this package computes a real
SHA-256. A digest that lies about its algorithm on the face of an evidence artifact is worse
than no digest at all.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

__all__ = [
    "DIGEST_PREFIX",
    "canonical_json",
    "is_wellformed_digest",
    "sha256_file",
    "sha256_text",
]

DIGEST_PREFIX = "sha256:"
_HEX_DIGITS = frozenset("0123456789abcdef")


def _canonicalize(obj: Any) -> Any:
    """Recursively sort mapping keys so serialisation is order-independent."""

    if isinstance(obj, dict):
        return {key: _canonicalize(obj[key]) for key in sorted(obj.keys())}
    if isinstance(obj, list | tuple):
        return [_canonicalize(item) for item in obj]
    return obj


def canonical_json(body: Any) -> str:
    """Serialise ``body`` to the canonical form that gets signed."""

    return json.dumps(_canonicalize(body), separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    """Return the ``sha256:``-prefixed digest of ``text`` encoded as UTF-8."""

    return DIGEST_PREFIX + hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Return the ``sha256:``-prefixed digest of a file, streamed so weights fit in memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return DIGEST_PREFIX + digest.hexdigest()


def is_wellformed_digest(value: str) -> bool:
    """Whether ``value`` is a syntactically valid ``sha256:<64 lowercase hex>`` digest.

    This is a shape check, not a verification. It exists because ``ScannerVerdict.model_digest``
    is unvalidated free text on the Rust side -- ``MockScanner`` sets it to
    ``format!("sha256:{}", self.id)``, which is not a digest at all -- so the binding has to be
    enforced on the way in.
    """

    if not value.startswith(DIGEST_PREFIX):
        return False
    hex_part = value[len(DIGEST_PREFIX) :]
    return len(hex_part) == 64 and set(hex_part) <= _HEX_DIGITS
