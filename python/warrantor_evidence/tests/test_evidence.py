"""Tests for warrantor_evidence — unit + cross-language interop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import warrantor_evidence as we

REPO_ROOT = Path(__file__).resolve().parents[3]
BUNDLE_PATH = REPO_ROOT / ".evidence_interop.json"

SAMPLE_CHAIN = [
    {
        "issuer": "spiffe://root",
        "subject": "spiffe://team",
        "capabilities": ["read", "write"],
        "not_before": 0,
        "not_after": 18446744073709551615,
        "token_digest": "sha256:aaa",
    },
    {
        "issuer": "spiffe://team",
        "subject": "spiffe://bot",
        "capabilities": ["read"],
        "not_before": 0,
        "not_after": 18446744073709551615,
        "token_digest": "sha256:bbb",
    },
]


# ---------------------------------------------------------------------------
# Unit: intersection + proof
# ---------------------------------------------------------------------------


def test_intersection_drops_write():
    assert we.recompute_intersection(SAMPLE_CHAIN) == ["read"]


def test_intersection_empty_chain():
    assert we.recompute_intersection([]) == []


def test_intersection_proof_recomputes():
    proof = we.compute_intersection_proof(SAMPLE_CHAIN)
    assert proof["algorithm"] == "warrantor-intersect-v1"
    assert len(proof["links_digest"]) == 64
    assert len(proof["result_digest"]) == 64


def test_verify_authority_correct():
    chain = SAMPLE_CHAIN
    effective = we.recompute_intersection(chain)
    proof = we.compute_intersection_proof(chain)
    we.verify_authority(
        {"chain": chain, "effective_capabilities": effective, "intersection_proof": proof}
    )


def test_verify_authority_expansion_rejected():
    chain = SAMPLE_CHAIN
    proof = we.compute_intersection_proof(chain)
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_authority(
            {
                "chain": chain,
                "effective_capabilities": ["read", "write"],
                "intersection_proof": proof,
            }
        )
    assert exc.value.code == "AUTHORITY"


def test_verify_authority_forged_proof_rejected():
    chain = SAMPLE_CHAIN
    effective = we.recompute_intersection(chain)
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_authority(
            {
                "chain": chain,
                "effective_capabilities": effective,
                "intersection_proof": {
                    "algorithm": "x",
                    "links_digest": "forged",
                    "result_digest": "forged",
                },
            }
        )
    assert exc.value.code == "AUTHORITY"


# ---------------------------------------------------------------------------
# Unit: canonical + PAE
# ---------------------------------------------------------------------------


def test_canonical_is_compact_and_sorted():
    pred = {"b": 2, "a": 1}
    c = we.canonical_predicate(pred)
    assert c == '{"a":1,"b":2}'


def test_dsse_pae_format():
    assert we.dsse_pae("hello") == b"DSSEv1 5 hello"


# ---------------------------------------------------------------------------
# Unit: verify_receipt rejects malformed
# ---------------------------------------------------------------------------


def _fake_receipt() -> dict:
    return {
        "predicate": {
            "binding": {
                "receipt_id": "x",
                "phase": "pre_commit",
                "nonce": "n",
                "issued_at": 1,
                "expires_at": 99,
                "enforcement_mode": "mediated",
            },
            "actor": {"principal": "a", "workload_id": "w", "svid_digest": "d"},
            "authority": {
                "chain": [],
                "effective_capabilities": [],
                "intersection_proof": {"algorithm": "", "links_digest": "", "result_digest": ""},
            },
            "decision": {
                "verdict": "allow",
                "engine": "e",
                "policy_digest": "p",
                "evaluated_at": 1,
            },
            "operation": {
                "class": "c",
                "target": "t",
                "method": "m",
                "parameters_digest": "pd",
                "reversible": True,
                "consequence_tier": "routine",
            },
        },
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "k",
            "public_key": "00" * 32,
            "value": "ff" * 64,
        },
    }


def test_verify_receipt_rejects_forged():
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_receipt(_fake_receipt())
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_receipt_rejects_bad_algorithm():
    r = _fake_receipt()
    r["signature"]["algorithm"] = "RSA"
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_receipt(r)
    assert exc.value.code == "SIGNATURE_ENVELOPE"


# ---------------------------------------------------------------------------
# Cross-language interop: verify the chain the Rust evidence crate issued.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not BUNDLE_PATH.exists(), reason="interop bundle not produced; run the Rust example first"
)
def test_interop_rust_chain_verifies():
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    assert bundle["schema"] == "warrantor.evidence.interop.v1"
    we.verify_chain(bundle["pre_commit"], bundle["post_commit"])  # must not raise


@pytest.mark.skipif(not BUNDLE_PATH.exists(), reason="interop bundle not produced")
def test_interop_tampered_post_commit_rejected():
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    post = bundle["post_commit"]
    post["predicate"]["actor"]["principal"] = "evil"  # tamper
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_chain(bundle["pre_commit"], post)
    assert exc.value.code == "INVALID_SIGNATURE"


@pytest.mark.skipif(not BUNDLE_PATH.exists(), reason="interop bundle not produced")
def test_interop_authority_spot_check():
    """Independently recompute the intersection from the chain in the receipt."""
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    chain = bundle["pre_commit"]["predicate"]["authority"]["chain"]
    claimed = bundle["pre_commit"]["predicate"]["authority"]["effective_capabilities"]
    recomputed = we.recompute_intersection(chain)
    assert recomputed == claimed, (
        f"intersection mismatch: recomputed={recomputed} claimed={claimed}"
    )
