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
    assert bundle["schema"] == "warrantor.evidence.interop.v2"
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


# ---------------------------------------------------------------------------
# Task 10.1 — the predicate version, and cross-language parity on refusing one
# ---------------------------------------------------------------------------


def test_predicate_type_is_the_same_string_rust_declares():
    """One constant, two languages. Read from the Rust source rather than retyped."""
    rust = (REPO_ROOT / "rust" / "evidence" / "src" / "lib.rs").read_text(encoding="utf-8")
    expected = f'pub const PREDICATE_TYPE: &str = "{we.PREDICATE_TYPE}";'
    assert expected in rust, (
        f"rust/evidence/src/lib.rs must declare {expected!r}. Two verifiers keyed on two different "
        "version strings would disagree about which rule to apply."
    )


def test_an_absent_version_is_v1_and_still_verifies_shape():
    """The paired control: a v1 predicate passes the version gate. Without this the gate could
    refuse everything and still look correct."""
    we.check_predicate_version(_fake_receipt()["predicate"])  # must not raise


def test_an_unknown_version_is_refused_with_the_same_code_rust_returns():
    predicate = _fake_receipt()["predicate"]
    predicate["predicate_version"] = "https://warrantor.dev/ActionReceipt/v9"
    with pytest.raises(we.EvidenceError) as exc:
        we.check_predicate_version(predicate)
    assert exc.value.code == "UNKNOWN_VERSION"
    assert "v9" in str(exc.value)


def test_the_recognized_version_passes_the_version_gate():
    predicate = _fake_receipt()["predicate"]
    predicate["predicate_version"] = we.PREDICATE_TYPE
    we.check_predicate_version(predicate)  # must not raise


def test_a_causal_section_with_no_version_is_refused():
    """The mirror image, and the one a dict-generic canonicalizer would otherwise wave through."""
    predicate = _fake_receipt()["predicate"]
    predicate["causality"] = {"queue_head": "00", "step_count": 0, "steps": []}
    with pytest.raises(we.EvidenceError) as exc:
        we.check_predicate_version(predicate)
    assert exc.value.code == "UNVERSIONED_CAUSALITY"


def test_verify_receipt_reports_the_version_not_the_signature():
    """`_fake_receipt` carries a deliberately bogus signature, so a verifier that checked the
    signature first would report INVALID_SIGNATURE about a receipt whose real problem is that this
    build has no rule for its format."""
    receipt = _fake_receipt()
    receipt["predicate"]["predicate_version"] = "https://warrantor.dev/ActionReceipt/v9"
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_receipt(receipt)
    assert exc.value.code == "UNKNOWN_VERSION"


@pytest.mark.skipif(not BUNDLE_PATH.exists(), reason="interop bundle not produced")
def test_interop_a_v1_and_a_v2_receipt_both_verify_in_the_same_run():
    """The compatibility claim across languages: adding two fields did not cost the old shape."""
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    v1 = bundle["v1_atomic"]
    v2 = bundle["v2_atomic"]
    assert "predicate_version" not in v1["predicate"], (
        "an absent field must stay absent on the wire, or every signature taken before Task 10.1 "
        "stops verifying"
    )
    assert "causality" not in v1["predicate"]
    assert v2["predicate"]["predicate_version"] == we.PREDICATE_TYPE
    assert v2["predicate"]["causality"]["step_count"] == 1
    we.verify_receipt(v1)
    we.verify_receipt(v2)


@pytest.mark.skipif(not BUNDLE_PATH.exists(), reason="interop bundle not produced")
def test_interop_a_correctly_signed_unknown_version_is_refused_by_python_too():
    """Rust refuses this receipt as UnknownVersion. Python must refuse the same bytes, and must not
    accept them merely because its canonicalizer is dict-generic and the signature happens to be
    valid."""
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    with pytest.raises(we.EvidenceError) as exc:
        we.verify_receipt(bundle["unknown_version"])
    assert exc.value.code == "UNKNOWN_VERSION"
