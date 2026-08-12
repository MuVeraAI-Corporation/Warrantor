"""Tests for the W3 containment conformance verify path."""
from __future__ import annotations

import pytest

import warrantor_containment_conformance as wcc


def test_canonical_report_sorted():
    assert wcc.canonical_report({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_forged_report_rejected():
    signed = {
        "report": {"subject_system": "x", "timestamp": 1},
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wcc.ConformanceError) as exc:
        wcc.verify_report(signed)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    signed = {"report": {"x": 1}, "signature_public_key": "00", "signature_value": "ff" * 64}
    with pytest.raises(wcc.ConformanceError) as exc:
        wcc.verify_report(signed)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
