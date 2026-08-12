"""Tests for the W9 spend verify path."""

from __future__ import annotations

import pytest

import warrantor_spend as ws


def test_canonical_body_sorted():
    assert ws.canonical_body({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_receipt_rejected():
    receipt = {
        "body": {
            "verdict": {"outcome": "allow"},
            "agent_id": "x",
            "task_id": "t",
            "timestamp": 1,
            "engine_version": "v",
        },
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(ws.SpendError) as exc:
        ws.verify_receipt(receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    receipt = {"body": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(ws.SpendError) as exc:
        ws.verify_receipt(receipt)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
