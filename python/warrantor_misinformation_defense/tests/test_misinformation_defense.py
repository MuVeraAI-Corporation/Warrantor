"""Tests for the W12 misinformation/CIB defense verify path."""

from __future__ import annotations

import pytest

import warrantor_misinformation_defense as wmd


def test_canonical_body_sorted():
    assert wmd.canonical_body({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_receipt_rejected():
    receipt = {
        "body": {
            "verdict": {"outcome": "clear"},
            "agent_id": "x",
            "target": "t",
            "content_hash": "h",
            "timestamp": 1,
            "plane_version": "v",
        },
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wmd.CibError) as exc:
        wmd.verify_receipt(receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    receipt = {"body": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(wmd.CibError) as exc:
        wmd.verify_receipt(receipt)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
