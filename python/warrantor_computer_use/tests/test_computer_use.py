"""Tests for the W8 computer-use verify path."""

from __future__ import annotations

import pytest

import warrantor_computer_use as wcu


def test_canonical_body_sorted():
    assert wcu.canonical_body({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_receipt_rejected():
    receipt = {
        "body": {
            "verdict": {"outcome": "allow"},
            "agent_id": "x",
            "timestamp": 1,
            "broker_version": "v",
        },
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wcu.ComputerUseError) as exc:
        wcu.verify_receipt(receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    receipt = {"body": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(wcu.ComputerUseError) as exc:
        wcu.verify_receipt(receipt)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
