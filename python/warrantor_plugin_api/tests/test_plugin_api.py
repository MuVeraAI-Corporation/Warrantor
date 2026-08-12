"""Tests for the X1 plugin API verify path."""

from __future__ import annotations

import pytest

import warrantor_plugin_api as wpa


def test_canonical_manifest_sorted():
    m = {"b": 2, "a": 1}
    assert (
        wpa.canonical_manifest(m, "sha256:x")
        == '{"artifact_digest":"sha256:x","manifest":{"a":1,"b":2}}'
    )


def test_verify_forged_plugin_rejected():
    plugin = {
        "manifest": {"plugin_id": "x", "plugin_type": "verdict_plugin"},
        "artifact_digest": "sha256:abc",
        "signature_public_key": "00" * 32,
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wpa.PluginError) as exc:
        wpa.verify_plugin(plugin)
    assert exc.value.code == "INVALID_SIGNATURE"


def test_verify_bad_key_length():
    plugin = {
        "manifest": {"x": 1},
        "artifact_digest": "d",
        "signature_public_key": "00",
        "signature_value": "ff" * 64,
    }
    with pytest.raises(wpa.PluginError) as exc:
        wpa.verify_plugin(plugin)
    assert exc.value.code == "SIGNATURE_ENVELOPE"
