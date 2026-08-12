"""Tests for the W11 CSAM defense verify path."""

from __future__ import annotations

import pytest

import warrantor_csam_defense as wcs


def test_canonical_body_sorted():
    assert wcs.canonical_body({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_receipt_rejected():
    receipt = {
        "body": {
            "verdict": {"outcome": "deny"},
            "content_hash": "h",
            "timestamp": 1,
            "plane_version": "v",
        },
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wcs.CsamError) as exc:
        wcs.verify_receipt(receipt)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    receipt = {"body": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(wcs.CsamError) as exc:
        wcs.verify_receipt(receipt)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
