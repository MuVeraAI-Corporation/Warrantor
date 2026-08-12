"""Tests for warrantor_agent_manifest — unit coverage + cross-language conformance.

The conformance test loads the SHARED vectors at ../../testvectors/agent-manifest/vectors.json
(the same file the Rust crate's conformance test loads) and asserts identical outcomes + error
codes. This is the cross-language contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import warrantor_agent_manifest as am

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "testvectors" / "agent-manifest" / "vectors.json"
)
MINIMAL = {
    "apiVersion": "agent.warrantor.io/v1",
    "kind": "AgentManifest",
    "name": "research-bot-1",
    "identity": "spiffe://yourcorp/agents/research-bot-1",
    "capabilities": ["read"],
    "policy_refs": ["pol_default"],
    "enforcement_mode": "observed",
}


# ---------------------------------------------------------------------------
# Unit: parse/validate
# ---------------------------------------------------------------------------


def test_minimal_valid_parses():
    m = am.parse_and_validate(json.dumps(MINIMAL))
    assert m["identity"] == "spiffe://yourcorp/agents/research-bot-1"
    assert m["capabilities"] == ["read"]


def test_missing_required_field_identity():
    bad = {k: v for k, v in MINIMAL.items() if k != "identity"}
    with pytest.raises(am.ManifestError) as exc:
        am.parse_and_validate(json.dumps(bad))
    assert exc.value.code == "MISSING_REQUIRED_FIELD"
    assert exc.value.field == "identity"


def test_invalid_capability_rejected():
    bad = {**MINIMAL, "capabilities": ["read", "deploy"]}
    with pytest.raises(am.ManifestError) as exc:
        am.parse_and_validate(json.dumps(bad))
    assert exc.value.code == "INVALID_CAPABILITY"
    assert exc.value.field == "capabilities"


def test_invalid_enforcement_mode_rejected():
    bad = {**MINIMAL, "enforcement_mode": "contained"}
    with pytest.raises(am.ManifestError) as exc:
        am.parse_and_validate(json.dumps(bad))
    assert exc.value.code == "INVALID_ENFORCEMENT_MODE"


def test_unexpected_field_rejected():
    bad = {**MINIMAL, "rogue": True}
    with pytest.raises(am.ManifestError) as exc:
        am.parse_and_validate(json.dumps(bad))
    assert exc.value.code == "UNEXPECTED_FIELD"
    assert exc.value.field == "rogue"


def test_bad_identity_not_spiffe():
    bad = {**MINIMAL, "identity": "https://yourcorp/agents/x"}
    with pytest.raises(am.ManifestError) as exc:
        am.parse_and_validate(json.dumps(bad))
    assert exc.value.code == "INVALID_IDENTITY"


def test_malformed_json():
    with pytest.raises(am.ManifestError) as exc:
        am.parse_and_validate("{not json")
    assert exc.value.code == "MALFORMED_JSON"


# ---------------------------------------------------------------------------
# Unit: canonical JSON + digest
# ---------------------------------------------------------------------------


def test_canonical_json_is_stable_and_sorted():
    m = am.parse_and_validate(json.dumps(MINIMAL))
    a = am.canonical_json(m)
    b = am.canonical_json(m)
    assert a == b, "canonical must be deterministic"
    # keys appear in sorted order
    positions = {
        key: a.find(f'"{key}"')
        for key in ("apiVersion", "capabilities", "enforcement_mode", "identity", "kind")
    }
    assert (
        positions["apiVersion"]
        < positions["capabilities"]
        < positions["enforcement_mode"]
        < positions["identity"]
        < positions["kind"]
    )
    assert " " not in a, "canonical must be compact (no whitespace)"


def test_digest_is_32_bytes_and_deterministic():
    m = am.parse_and_validate(json.dumps(MINIMAL))
    d1 = am.digest(m)
    d2 = am.digest(m)
    assert d1 == d2
    assert len(d1) == 32


def test_optional_fields_omitted_from_canonical():
    """A minimal manifest's canonical form must not include absent optional keys."""
    m = am.parse_and_validate(json.dumps(MINIMAL))
    canon = am.canonical_json(m)
    assert "description" not in canon
    assert "dependencies" not in canon
    assert "attestation" not in canon
    assert "version" not in canon


# ---------------------------------------------------------------------------
# Unit: Ed25519 sign / verify / tamper
# ---------------------------------------------------------------------------


def test_signature_round_trip_verifies():
    m = am.parse_and_validate(json.dumps(MINIMAL))
    priv, _ = am.generate_keypair()
    signed = am.sign(m, priv, "test-key-1")
    am.verify(signed)  # must not raise


def test_tampered_manifest_fails_verification():
    m = am.parse_and_validate(json.dumps(MINIMAL))
    priv, _ = am.generate_keypair()
    signed = am.sign(m, priv, "test-key-1")
    signed["manifest"]["name"] = "evil-twin"  # tamper AFTER signing
    with pytest.raises(am.ManifestError) as exc:
        am.verify(signed)
    assert exc.value.code == "SIGNATURE"


def test_bad_public_key_length_rejected():
    m = am.parse_and_validate(json.dumps(MINIMAL))
    priv, _ = am.generate_keypair()
    signed = am.sign(m, priv, "test-key-1")
    signed["signature"]["public_key"] = "00"  # wrong length
    with pytest.raises(am.ManifestError) as exc:
        am.verify(signed)
    assert exc.value.code == "SIGNATURE_ENVELOPE"


# ---------------------------------------------------------------------------
# Cross-language conformance: the shared vectors
# ---------------------------------------------------------------------------


def _load_vectors() -> list[dict]:
    assert VECTORS_PATH.exists(), f"vectors missing: {VECTORS_PATH}"
    root = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    vectors = root["vectors"]
    assert isinstance(vectors, list) and vectors, (
        "vectors.json must contain a non-empty 'vectors' array"
    )
    return vectors


def test_all_conformance_vectors_pass():
    vectors = _load_vectors()
    names = [v["name"] for v in vectors]
    assert len(names) == len(set(names)), (
        "vector names must be unique (silent dedup is a conformance hazard)"
    )

    failures = []
    for v in vectors:
        name = v["name"]
        manifest_json = json.dumps(v["manifest"])
        expected = v["expected"]
        expected_valid = expected["valid"]

        try:
            am.parse_and_validate(manifest_json)
            parsed_valid = True
            err = None
        except am.ManifestError as e:
            parsed_valid = False
            err = e

        if expected_valid and parsed_valid:
            continue  # pass
        if not expected_valid and not parsed_valid:
            want_code = expected.get("error_code")
            want_field = expected.get("error_field")
            if err.code != want_code:  # type: ignore[union-attr]
                failures.append(f"{name}: code want={want_code} got={err.code}")  # type: ignore[union-attr]
            elif want_field is not None and err.field != want_field:  # type: ignore[union-attr]
                failures.append(f"{name}: field want={want_field} got={err.field}")  # type: ignore[union-attr]
            continue  # pass
        if expected_valid and not parsed_valid:
            failures.append(f"{name}: expected VALID, got {err}")  # type: ignore[arg-type]
            continue
        # parsed_valid and not expected_valid
        want_code = expected.get("error_code")
        failures.append(f"{name}: expected INVALID ({want_code}), parsed VALID")

    assert not failures, f"{len(failures)} of {len(vectors)} vectors FAILED:\n  " + "\n  ".join(
        failures
    )


def test_vector_count_is_expected():
    """Guards against a silently-shrinking corpus."""
    vectors = _load_vectors()
    assert len(vectors) == 13, f"expected 13 manifest vectors; got {len(vectors)}"
