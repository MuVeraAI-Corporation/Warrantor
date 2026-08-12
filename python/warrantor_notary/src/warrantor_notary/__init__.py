"""W1 Notary — third-party Verify path for WAR receipts.

The verdict function (spec 11) is implemented **once**, in Rust. This package does NOT
re-implement any gate (spec 11 §1: *no security invariant may have two authoritative
implementations*). What it does is the thing the README calls &ldquo;the test that matters&rdquo;:
verify a receipt the Rust notary issued, with no privileged access and no shared secret, and
independently recompute the authority intersection to confirm the receipt's claim.

Public surface:

- :func:`verify_receipt` — Ed25519 verification over canonical-JSON receipt bytes.
- :func:`effective_capabilities` — the capability-algebra intersection (spec 06). Pure set
  arithmetic over the delegation chain; a third party can recompute this to spot-check a receipt's
  claimed ``effective_capabilities``.
- :func:`canonical_receipt_body` — the deterministic serialization (RFC 8785-shaped) both sides agree on.
- :func:`verify_bundle` — verify every entry in an interop bundle produced by the Rust example.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "NotaryError",
    "canonical_receipt_body",
    "effective_capabilities",
    "receipt_digest_hex",
    "verify_bundle",
    "verify_receipt",
]


class NotaryError(Exception):
    """Raised on receipt-verification or intersection-recomputation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785-shaped) — matches the Rust crate byte-for-byte.
# ---------------------------------------------------------------------------


def _canonicalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonicalize(x) for x in obj]
    return obj


def canonical_receipt_body(body: dict[str, Any]) -> str:
    """Deterministic serialization of the receipt body.

    A third party recomputing this from the same body gets byte-identical output, which is what
    makes the signature verifiable. Matches the Rust ``canonical_receipt_body`` exactly.
    """
    return json.dumps(_canonicalize(body), separators=(",", ":"), ensure_ascii=False)


def receipt_digest_hex(body: dict[str, Any]) -> str:
    """SHA-256 of the canonical bytes — what other receipts chain to."""
    return hashlib.sha256(canonical_receipt_body(body).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Verify — the third-party path. No privileged access, no shared secret.
# ---------------------------------------------------------------------------


def verify_receipt(receipt: dict[str, Any]) -> None:
    """Verify a WAR receipt's Ed25519 signature over its canonical body.

    Raises :class:`NotaryError` (code ``SIGNATURE_ENVELOPE`` or ``INVALID_SIGNATURE``) on any
    failure. A third party calling this needs nothing from the issuer except the receipt itself.
    """
    if not isinstance(receipt, dict):
        raise NotaryError("MALFORMED", "receipt must be an object")
    body = receipt.get("body")
    signature = receipt.get("signature")
    if not isinstance(body, dict) or not isinstance(signature, dict):
        raise NotaryError("SIGNATURE_ENVELOPE", "receipt missing body or signature")

    if signature.get("algorithm") != "Ed25519":
        raise NotaryError(
            "SIGNATURE_ENVELOPE", f"unsupported algorithm: {signature.get('algorithm')!r}"
        )
    try:
        pub_bytes = bytes.fromhex(signature["public_key"])
    except (KeyError, ValueError) as exc:
        raise NotaryError("SIGNATURE_ENVELOPE", f"public_key hex: {exc}") from exc
    if len(pub_bytes) != 32:
        raise NotaryError(
            "SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}"
        )
    try:
        sig_bytes = bytes.fromhex(signature["value"])
    except (KeyError, ValueError) as exc:
        raise NotaryError("SIGNATURE_ENVELOPE", f"signature hex: {exc}") from exc
    if len(sig_bytes) != 64:
        raise NotaryError("SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}")

    canonical = canonical_receipt_body(body).encode("utf-8")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except ValueError as exc:
        raise NotaryError("SIGNATURE_ENVELOPE", f"public_key: {exc}") from exc
    try:
        public_key.verify(sig_bytes, canonical)
    except InvalidSignature as exc:
        raise NotaryError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from exc


# ---------------------------------------------------------------------------
# Authority-intersection spot-check — the capability algebra (spec 06).
#
# This is NOT a re-implementation of the verdict gates (forbidden by spec 11 §1). It is the pure
# set-intersection over the delegation chain, which a third party can recompute to confirm a
# receipt's claimed effective_capabilities is correct. The verdict function uses this inside gate 5;
# a third party uses it to audit the receipt.
# ---------------------------------------------------------------------------


def effective_capabilities(actor: dict[str, Any]) -> list[str]:
    """The capability intersection across the actor's own capabilities and every chain link.

    A capability is effective iff it appears in the actor's own set AND in every link of the chain
    (the union trap, spec 12: a single link dropping a capability removes it). Returns a sorted list
    so the result is deterministic and comparable across languages.
    """
    own = set(actor.get("own_capabilities", []))
    sets = [own]
    for link in actor.get("delegation_chain", []):
        sets.append(set(link.get("capabilities", [])))
    if not sets:
        return []
    result = sets[0]
    for s in sets[1:]:
        result = result & s
    return sorted(result)


# ---------------------------------------------------------------------------
# Bundle verification — the interop entry point.
# ---------------------------------------------------------------------------


def verify_bundle(bundle: dict[str, Any]) -> tuple[int, int]:
    """Verify every entry in an interop bundle produced by the Rust example.

    For each entry: (1) verify the receipt signature, (2) for Allow verdicts, recompute the
    authority intersection from the request's actor and assert it matches the receipt's claimed
    effective_capabilities. Returns ``(verified, intersection_spot_checks_passed)``.
    """
    if bundle.get("schema") != "warrantor.notary.interop.v1":
        raise NotaryError("MALFORMED", f"unexpected bundle schema: {bundle.get('schema')!r}")
    entries = bundle.get("entries", [])
    verified = 0
    spot_checks = 0
    for entry in entries:
        receipt = entry["receipt"]
        verify_receipt(receipt)  # raises on failure
        verified += 1
        # Intersection spot-check for Allow verdicts.
        verdict_obj = receipt["body"]["verdict"]
        if verdict_obj.get("outcome") == "allow":
            recomputed = effective_capabilities(entry["request"]["actor"])
            claimed = verdict_obj.get("effective_capabilities", [])
            if recomputed != claimed:
                raise NotaryError(
                    "INTERSECTION_MISMATCH",
                    f"{entry['name']}: effective_capabilities recomputed={recomputed} claimed={claimed}",
                )
            spot_checks += 1
    return verified, spot_checks
