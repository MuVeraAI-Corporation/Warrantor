"""Tests for the DU1 post-quantum verify path."""

from __future__ import annotations

import pytest

import warrantor_post_quantum as wpq


def test_canonical_json_sorted():
    assert wpq.canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_payload_rejected():
    dual = {
        "payload": {"action": "test"},
        "classical": {
            "algorithm": "ed25519",
            "key_id": "k",
            "public_key_hex": "00" * 32,
            "signature_hex": "ff" * 64,
        },
        "post_quantum": None,
    }
    with pytest.raises(wpq.DuError) as exc:
        wpq.verify_classical(dual)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    dual = {
        "payload": {"x": 1},
        "classical": {"public_key_hex": "00", "signature_hex": "ff" * 64},
    }
    with pytest.raises(wpq.DuError) as exc:
        wpq.verify_classical(dual)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
