"""Tests for the W10 content moderation verify path."""

from __future__ import annotations

import pytest

import warrantor_content_moderation as wcm


def test_canonical_body_sorted():
    assert wcm.canonical_body({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_receipt_rejected():
    receipt = {
        "body": {
            "verdict": {"outcome": "allow"},
            "content_digest": "d",
            "timestamp": 1,
            "plane_version": "v",
        },
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wcm.CmError) as exc:
        wcm.verify_receipt(receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    receipt = {"body": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(wcm.CmError) as exc:
        wcm.verify_receipt(receipt)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
