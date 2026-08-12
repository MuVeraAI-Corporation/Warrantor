"""Tests for the SG1 self-governance verify path."""

from __future__ import annotations

import pytest

import warrantor_self_governance as wsg


def test_canonical_report_sorted():
    assert wsg.canonical_report({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_report_rejected():
    signed = {
        "report": {"overall_conformant": True, "timestamp": 1},
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wsg.SgError) as exc:
        wsg.verify_report(signed)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    signed = {"report": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(wsg.SgError) as exc:
        wsg.verify_report(signed)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
