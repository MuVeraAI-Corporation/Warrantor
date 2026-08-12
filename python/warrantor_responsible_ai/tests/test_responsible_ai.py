"""Tests for the RA1 responsible-AI verify path."""

from __future__ import annotations

import pytest

import warrantor_responsible_ai as wra


def test_canonical_block_sorted():
    assert (
        wra.canonical_block({"b": 2, "a": 1}, "act-1")
        == '{"action_id":"act-1","block":{"a":1,"b":2}}'
    )


def test_verify_forged_block_rejected():
    signed = {
        "block": {"bias_audit": {"checked": True, "score": 0.1}},
        "action_id": "x",
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wra.RaError) as exc:
        wra.verify_ra_block(signed)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    signed = {
        "block": {"x": 1},
        "action_id": "a",
        "signature_public_key": "00",
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wra.RaError) as exc:
        wra.verify_ra_block(signed)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
