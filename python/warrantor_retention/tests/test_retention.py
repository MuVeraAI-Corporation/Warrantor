"""Tests for the AumOS data retention + GDPR tombstone engine."""

from __future__ import annotations

import copy
import time

import pytest

from warrantor_retention import (
    DEFAULT_POLICIES,
    INDEFINITE,
    REDACTED,
    RetentionEngine,
    RetentionPolicy,
    TombstoneError,
)

_SECONDS_PER_DAY = 86_400.0


# ---------------------------------------------------------------------------
# Policy management
# ---------------------------------------------------------------------------


def test_engine_loads_default_policies():
    engine = RetentionEngine()
    data_types = {p.data_type for p in DEFAULT_POLICIES}
    for dt in ("audit_logs", "attestation_ledger", "agent_receipts", "eval_results", "pii_data"):
        assert dt in data_types
        assert engine.has_policy(dt)


def test_default_policies_have_expected_windows():
    by_type = {p.data_type: p for p in DEFAULT_POLICIES}
    assert by_type["audit_logs"].retention_days == 2555
    assert by_type["audit_logs"].action == "archive"
    assert by_type["attestation_ledger"].retention_days == INDEFINITE
    assert by_type["eval_results"].retention_days == 90
    assert by_type["eval_results"].action == "delete"
    assert by_type["pii_data"].retention_days == 365
    assert by_type["pii_data"].action == "anonymize"


def test_register_policy_adds_and_replaces():
    engine = RetentionEngine()
    engine.register_policy(RetentionPolicy("custom_log", retention_days=30, action="delete"))
    assert engine.get_policy("custom_log").retention_days == 30
    # Replace.
    engine.register_policy(RetentionPolicy("custom_log", retention_days=60, action="archive"))
    assert engine.get_policy("custom_log").retention_days == 60
    assert engine.get_policy("custom_log").action == "archive"


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        RetentionPolicy("", retention_days=10)
    with pytest.raises(ValueError):
        RetentionPolicy("x", retention_days=-2)
    with pytest.raises(ValueError):
        RetentionPolicy("x", retention_days=10, action="vaporise")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Expiry checking
# ---------------------------------------------------------------------------


def test_check_expired_within_window():
    engine = RetentionEngine()
    now = time.time()
    # A 1-second-old audit log is well inside the 7-year window.
    assert engine.check_expired("audit_logs", now - 1, now=now) is False


def test_check_expired_past_window():
    engine = RetentionEngine()
    now = time.time()
    # eval_results: 90 days. A 100-day-old record is expired.
    old = now - (100 * _SECONDS_PER_DAY)
    assert engine.check_expired("eval_results", old, now=now) is True
    assert engine.retention_action("eval_results") == "delete"


def test_check_expired_indefinite_never_expires():
    engine = RetentionEngine()
    now = time.time()
    # The attestation ledger is indefinite — even a 1000-year-old entry is kept.
    ancient = now - (1000 * 365 * _SECONDS_PER_DAY)
    assert engine.check_expired("attestation_ledger", ancient, now=now) is False


def test_check_expired_unknown_data_type_fail_closed():
    engine = RetentionEngine()
    now = time.time()
    # No policy => never expire (we don't auto-delete what we don't understand).
    assert engine.check_expired("unknown_type", now - 10_000_000, now=now) is False
    assert engine.retention_action("unknown_type") is None


def test_check_expired_boundary():
    engine = RetentionEngine()
    now = 1_000_000_000.0
    # eval_results is 90 days. A record exactly 90 days old is expired (>=).
    boundary = now - (90 * _SECONDS_PER_DAY)
    assert engine.check_expired("eval_results", boundary, now=now) is True
    # One second newer than the boundary is not expired.
    just_before = now - (90 * _SECONDS_PER_DAY) + 1
    assert engine.check_expired("eval_results", just_before, now=now) is False


# ---------------------------------------------------------------------------
# GDPR tombstone (apply_tombstone)
# ---------------------------------------------------------------------------


def test_apply_tombstone_redacts_named_fields():
    engine = RetentionEngine()
    record = {
        "id": "rec-1",
        "user_email": "alice@example.com",
        "ssn": "123-45-6789",
        "prompt": "what is the weather",
    }
    out = engine.apply_tombstone(record, ["user_email", "ssn"])
    # Sensitive fields replaced; non-sensitive preserved.
    assert out["user_email"] == REDACTED
    assert out["ssn"] == REDACTED
    assert out["prompt"] == "what is the weather"
    assert out["id"] == "rec-1"
    # A tombstone marker is present and auditable.
    assert out["_tombstone"]["erased"] is True
    assert "user_email" in out["_tombstone"]["fields"]
    assert "ssn" in out["_tombstone"]["fields"]
    assert "hmac" in out["_tombstone"]


def test_apply_tombstone_does_not_mutate_input():
    engine = RetentionEngine()
    record = {"id": "rec-1", "email": "a@b.c"}
    snapshot = copy.deepcopy(record)
    _ = engine.apply_tombstone(record, ["email"])
    # The original dict is untouched.
    assert record == snapshot


def test_apply_tombstone_preserves_record_structure():
    """The append-only ledger stays intact: keys and key order preserved."""
    engine = RetentionEngine()
    record = {
        "id": "rec-1",
        "ts": 1234567890,
        "hash": "deadbeef",
        "secret_payload": "TOPSECRET",
    }
    out = engine.apply_tombstone(record, ["secret_payload"])
    # All original keys are still present (plus the new _tombstone marker).
    for k in record:
        assert k in out
    # The structure (number of keys) is preserved + 1 for the marker.
    assert len(out) == len(record) + 1


def test_apply_tombstone_handles_nested_fields():
    engine = RetentionEngine()
    record = {
        "id": "rec-1",
        "secret": "outer",
        "nested": {"secret": "inner", "keep": "yes"},
        "items": [{"secret": "list-item"}, {"keep": "ok"}],
    }
    out = engine.apply_tombstone(record, ["secret"])
    assert out["secret"] == REDACTED
    assert out["nested"]["secret"] == REDACTED
    assert out["nested"]["keep"] == "yes"
    assert out["items"][0]["secret"] == REDACTED
    assert out["items"][1]["keep"] == "ok"


def test_apply_tombstone_records_missing_fields():
    engine = RetentionEngine()
    record = {"id": "rec-1", "email": "a@b.c"}
    out = engine.apply_tombstone(record, ["email", "nonexistent_field"])
    assert out["_tombstone"]["missing"] == ["nonexistent_field"]
    assert "nonexistent_field" not in out["_tombstone"]["fields"]


def test_apply_tombstone_rejects_bad_inputs():
    engine = RetentionEngine()
    with pytest.raises(TombstoneError):
        engine.apply_tombstone("not a dict", ["x"])  # type: ignore[arg-type]
    with pytest.raises(TombstoneError):
        engine.apply_tombstone({"x": 1}, [123])  # type: ignore[list-item]


def test_apply_tombstone_hmac_is_tamper_evident():
    """The HMAC over the erased field list changes if the list changes."""
    engine = RetentionEngine()
    record = {"a": 1, "b": 2}
    secret = b"real-secret"
    out1 = engine.apply_tombstone(record, ["a"], secret=secret)
    out2 = engine.apply_tombstone(record, ["a", "b"], secret=secret)
    assert out1["_tombstone"]["hmac"] != out2["_tombstone"]["hmac"]
    # Same inputs => same HMAC (deterministic).
    out1b = engine.apply_tombstone(record, ["a"], secret=secret)
    assert out1["_tombstone"]["hmac"] == out1b["_tombstone"]["hmac"]


# ---------------------------------------------------------------------------
# Cryptographic key shredding
# ---------------------------------------------------------------------------


def test_key_shred_deletes_key_keeps_store_intact():
    engine = RetentionEngine()
    store = {"rec-1": b"super-secret-key-bytes", "rec-2": b"another-key"}
    ok = engine.key_shred("rec-1", store)
    assert ok is True
    assert "rec-1" not in store
    # Other keys untouched.
    assert store["rec-2"] == b"another-key"


def test_key_shred_idempotent_returns_false_when_absent():
    engine = RetentionEngine()
    store: dict[str, bytes] = {"rec-1": b"k"}
    assert engine.key_shred("rec-1", store) is True
    # Second shred on the same id returns False (already gone).
    assert engine.key_shred("rec-1", store) is False


def test_key_shred_records_audit_entry():
    engine = RetentionEngine()
    store = {"rec-x": b"keydata"}
    now = 1_700_000_000.0
    engine.key_shred("rec-x", store, now=now)
    log = engine.shred_log()
    assert len(log) == 1
    assert log[0]["record_id"] == "rec-x"
    assert log[0]["action"] == "key_shred"
    assert log[0]["shredded_at"] == now


def test_key_shred_rejects_bad_inputs():
    engine = RetentionEngine()
    with pytest.raises(TombstoneError):
        engine.key_shred("", {"a": b"x"})
    with pytest.raises(TombstoneError):
        engine.key_shred("rec", "not-a-mapping")  # type: ignore[arg-type]
    # An immutable mapping (frozen set / tuple) is rejected.
    with pytest.raises((TombstoneError, TypeError)):
        engine.key_shred("rec", ("k", "v"))  # type: ignore[arg-type]


def test_key_shred_can_be_silently_audited_off():
    engine = RetentionEngine()
    store = {"rec-1": b"k"}
    engine.key_shred("rec-1", store, audit=False)
    assert engine.shred_log() == []


# ---------------------------------------------------------------------------
# End-to-end GDPR flow
# ---------------------------------------------------------------------------


def test_gdpr_erasure_end_to_end():
    """A record can be ledger-tombstoned AND key-shredded: the entry survives,
    the sensitive content is REDACTED, and the encryption key is gone — so the
    underlying ciphertext is cryptographically inaccessible."""
    engine = RetentionEngine()
    record = {
        "id": "rec-e2e",
        "user_email": "subject@example.com",
        "home_address": "42 Private Rd",
        "ledger_hash": "abc123",
        "ciphertext_ref": "blob://encrypted/rec-e2e",
    }
    key_store = {"rec-e2e": b"the-only-key-that-could-decrypt-it"}

    # 1. Tombstone the PII fields.
    tombstoned = engine.apply_tombstone(record, ["user_email", "home_address"])
    assert tombstoned["user_email"] == REDACTED
    assert tombstoned["home_address"] == REDACTED
    # The ledger evidence is preserved.
    assert tombstoned["ledger_hash"] == "abc123"
    assert tombstoned["ciphertext_ref"] == "blob://encrypted/rec-e2e"

    # 2. Shred the encryption key.
    assert engine.key_shred("rec-e2e", key_store) is True
    assert "rec-e2e" not in key_store
    # The ciphertext blob reference still exists in the record — but without
    # the key it can no longer be decrypted. The ledger is append-only intact.
    assert tombstoned["ciphertext_ref"] == "blob://encrypted/rec-e2e"
