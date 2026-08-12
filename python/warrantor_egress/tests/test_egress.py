"""Tests for the W5 egress verify path."""

from __future__ import annotations

import pytest

import warrantor_egress as we


def test_canonical_body_sorted():
    body = {"b": 2, "a": 1}
    assert we.canonical_body(body) == '{"a":1,"b":2}'


def test_verify_forged_receipt_rejected():
    receipt = {
        "body": {
            "verdict": {"outcome": "allow"},
            "capability": "x",
            "timestamp": 1,
            "broker_version": "v",
        },
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(we.EgressError) as exc:
        we.verify_receipt(receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    receipt = {"body": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(we.EgressError) as exc:
        we.verify_receipt(receipt)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
