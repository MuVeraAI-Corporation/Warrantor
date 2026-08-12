"""W2 Evidence envelope — third-party Verify path for WAR receipts.

The pre_commit→post_commit chaining (spec 01, WAR v2.0). Signing and the commit gate are
Rust-only (spec 01 §4: *only the Rust trusted core signs*); this package verifies chains and
receipts with no privileged access — any third party can confirm a chain is well-formed, the
signatures are authentic, the authority intersection recomputes correctly (I-02), and the commit
gate holds (I-07).

Public surface:

- :func:`verify_receipt` — Ed25519 over DSSE PAE of the canonical predicate.
- :func:`verify_chain` — commit gate + both signatures + authority intersection.
- :func:`recompute_intersection` — the capability-algebra spot-check (I-02).
- :func:`verify_authority` — intersection + proof consistency.
- :func:`canonical_predicate` / :func:`dsse_pae` — the canonical forms both sides agree on.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "EvidenceError",
    "canonical_predicate",
    "check_mode_honesty",
    "compute_intersection_proof",
    "dsse_pae",
    "recompute_intersection",
    "verify_authority",
    "verify_chain",
    "verify_receipt",
]


class EvidenceError(Exception):
    """Raised on receipt/chain verification failure."""

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


def canonical_predicate(predicate: dict[str, Any]) -> str:
    """JCS-canonical JSON of the predicate. Matches the Rust ``canonical_predicate`` exactly."""
    return json.dumps(_canonicalize(predicate), separators=(",", ":"), ensure_ascii=False)


def dsse_pae(payload: str) -> bytes:
    """DSSE Pre-Auth Encoding: ``DSSEv1 {len} {payload}``. The signed bytes (spec 01 §4)."""
    payload_bytes = payload.encode("utf-8")
    return b"DSSEv1 " + str(len(payload_bytes)).encode() + b" " + payload_bytes


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Intersection proof (spec 01 §3.3, I-02) — recomputable by any verifier.
# ---------------------------------------------------------------------------


def recompute_intersection(chain: list[dict[str, Any]]) -> list[str]:
    """The capability intersection across the chain. A capability is effective iff it appears
    in EVERY link. Sorted for determinism."""
    if not chain:
        return []
    sets = [set(link.get("capabilities", [])) for link in chain]
    result = sets[0]
    for s in sets[1:]:
        result = result & s
    return sorted(result)


def compute_intersection_proof(chain: list[dict[str, Any]]) -> dict[str, str]:
    """Recompute the intersection proof from a chain (spec 01 §3.3)."""
    canon_chain = json.dumps(_canonicalize(chain), separators=(",", ":"), ensure_ascii=False)
    links_digest = _sha256_hex(canon_chain)
    result = recompute_intersection(chain)
    result_digest = _sha256_hex(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
    return {
        "algorithm": "warrantor-intersect-v1",
        "links_digest": links_digest,
        "result_digest": result_digest,
    }


def verify_authority(authority: dict[str, Any]) -> None:
    """Verify the authority block (I-02): recompute the intersection, reject expansion + forged proof."""
    chain = authority.get("chain", [])
    recomputed = recompute_intersection(chain)
    claimed = authority.get("effective_capabilities", [])
    if recomputed != claimed:
        raise EvidenceError(
            "AUTHORITY",
            f"effective_capabilities {claimed} != recomputed intersection {recomputed} (I-02)",
        )
    expected_proof = compute_intersection_proof(chain)
    if expected_proof != authority.get("intersection_proof"):
        raise EvidenceError(
            "AUTHORITY", "intersection_proof inconsistent with chain (forged; I-02)"
        )


# ---------------------------------------------------------------------------
# Verify receipt — Ed25519 over DSSE PAE (spec 01 §4)
# ---------------------------------------------------------------------------


def verify_receipt(receipt: dict[str, Any]) -> None:
    """Verify a single WAR receipt's Ed25519 signature over the DSSE PAE of the canonical predicate."""
    predicate = receipt.get("predicate")
    signature = receipt.get("signature")
    if not isinstance(predicate, dict) or not isinstance(signature, dict):
        raise EvidenceError("SIGNATURE_ENVELOPE", "receipt missing predicate or signature")

    if signature.get("algorithm") != "Ed25519":
        raise EvidenceError(
            "SIGNATURE_ENVELOPE", f"unsupported algorithm: {signature.get('algorithm')!r}"
        )
    try:
        pub_bytes = bytes.fromhex(signature["public_key"])
    except (KeyError, ValueError) as exc:
        raise EvidenceError("SIGNATURE_ENVELOPE", f"public_key hex: {exc}") from exc
    if len(pub_bytes) != 32:
        raise EvidenceError(
            "SIGNATURE_ENVELOPE", f"public_key must be 32 bytes, got {len(pub_bytes)}"
        )
    try:
        sig_bytes = bytes.fromhex(signature["value"])
    except (KeyError, ValueError) as exc:
        raise EvidenceError("SIGNATURE_ENVELOPE", f"signature hex: {exc}") from exc
    if len(sig_bytes) != 64:
        raise EvidenceError(
            "SIGNATURE_ENVELOPE", f"signature must be 64 bytes, got {len(sig_bytes)}"
        )

    pae = dsse_pae(canonical_predicate(predicate))
    try:
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except ValueError as exc:
        raise EvidenceError("SIGNATURE_ENVELOPE", f"public_key: {exc}") from exc
    try:
        public_key.verify(sig_bytes, pae)
    except InvalidSignature as exc:
        raise EvidenceError("INVALID_SIGNATURE", "Ed25519 signature does not verify") from exc


# ---------------------------------------------------------------------------
# Verify chain — the commit gate (I-07) + both signatures + authority (I-02)
# ---------------------------------------------------------------------------


def verify_chain(pre_commit: dict[str, Any], post_commit: dict[str, Any]) -> None:
    """Verify a pre_commit→post_commit chain (spec 01 §5, I-07).

    Checks: both signatures verify; the post_commit's parent_receipt == pre_commit's receipt_id
    (commit gate); pre_commit has no outcome; post_commit has outcome; authority intersection
    recomputes correctly on both.
    """
    verify_receipt(pre_commit)
    verify_receipt(post_commit)

    pre_binding = pre_commit["predicate"]["binding"]
    post_binding = post_commit["predicate"]["binding"]

    if pre_binding.get("phase") != "pre_commit":
        raise EvidenceError("PHASE", "pre_commit must have phase=pre_commit")
    if pre_commit["predicate"].get("outcome") is not None:
        raise EvidenceError("PHASE", "pre_commit must not carry an outcome")
    if post_binding.get("phase") != "post_commit":
        raise EvidenceError("PHASE", "post_commit must have phase=post_commit")
    if post_commit["predicate"].get("outcome") is None:
        raise EvidenceError("PHASE", "post_commit must carry an outcome")

    parent = post_binding.get("parent_receipt")
    expected = pre_binding["receipt_id"]
    if parent != expected:
        raise EvidenceError(
            "COMMIT_GATE",
            f"post_commit parent_receipt ({parent}) != pre_commit receipt_id ({expected})",
        )

    verify_authority(pre_commit["predicate"]["authority"])
    verify_authority(post_commit["predicate"]["authority"])


def check_mode_honesty(receipt: dict[str, Any], claims_non_bypassable: bool) -> None:
    """Reject an advisory receipt claiming non-bypassability (spec 01 §6)."""
    mode = receipt["predicate"]["binding"].get("enforcement_mode")
    if claims_non_bypassable and mode == "advisory":
        raise EvidenceError(
            "ENFORCEMENT_MODE", "advisory receipt cannot assert non-bypassability (§6)"
        )
