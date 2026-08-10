"""AumOS data retention policy engine and GDPR right-to-erasure (tombstone) support.

This module implements:

  * **Retention policies** — declarative rules mapping a data type to a retention
    window (in days) and an action to take when the window expires
    (``delete`` / ``anonymize`` / ``archive``).
  * **Expiry checking** — given a data type and a timestamp, determine whether
    the data is past its retention window.
  * **GDPR right-to-erasure** — replace the sensitive content of a record while
    preserving its structural identity (the "tombstone"). The append-only
    attestation ledger stays intact; only the sensitive payload is shredded.
  * **Cryptographic key shredding** — for records whose confidentiality depends
    on an encryption key (the recommended pattern for AumOS audit records),
    erasing the key renders the ciphertext permanently unreadable without
    deleting a single byte of the ledger.

Default policies are pre-registered (SOX 7-year audit retention, 90-day eval
results, 1-year PII, indefinite attestation ledger).

Usage::

    from warrantor_retention import RetentionEngine, RetentionPolicy

    engine = RetentionEngine()            # pre-loaded with defaults
    engine.register_policy(RetentionPolicy("custom_log", retention_days=30,
                                           action="delete"))
    if engine.check_expired("audit_logs", old_timestamp):
        ...  # apply the configured action

    redacted = engine.apply_tombstone(record,
                                      fields_to_erase=["user_email", "ssn"])
    engine.key_shred(record_id, key_store)
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "DEFAULT_POLICIES",
    "INDEFINITE",
    "REDACTED",
    "RetentionAction",
    "RetentionEngine",
    "RetentionPolicy",
    "TombstoneError",
]

# The marker written into a record field when it has been tombstoned. Kept short
# and stable so downstream tooling can detect it without parsing.
REDACTED = "REDACTED"

# Sentinel retention-days value meaning "never expire". Data types with this
# policy are retained forever (e.g. the append-only attestation ledger).
INDEFINITE = -1

RetentionAction = Literal["delete", "anonymize", "archive"]
_VALID_ACTIONS: frozenset[str] = frozenset({"delete", "anonymize", "archive"})

# Number of seconds in a day. Centralised so the expiry math is uniform.
_SECONDS_PER_DAY = 86_400.0


@dataclass(frozen=True)
class RetentionPolicy:
    """A single retention rule.

    Attributes:
        data_type:      logical name of the data type this policy governs
                        (e.g. ``"audit_logs"``, ``"pii_data"``).
        retention_days: number of days to retain the data before ``action``
                        fires. Use ``INDEFINITE`` (``-1``) to retain forever.
        action:         what to do once the window expires — one of
                        ``"delete"``, ``"anonymize"``, ``"archive"``.
        description:    optional human-readable note.
    """

    data_type: str
    retention_days: int
    action: RetentionAction = "delete"
    description: str = ""

    def __post_init__(self) -> None:
        if not self.data_type:
            raise ValueError("data_type must be a non-empty string")
        if self.retention_days < INDEFINITE:
            raise ValueError(
                f"retention_days must be >= {INDEFINITE} (INDEFINITE); got {self.retention_days}"
            )
        if self.action not in _VALID_ACTIONS:
            raise ValueError(f"action must be one of {sorted(_VALID_ACTIONS)}; got {self.action!r}")


# Default policies shipped with AumOS. Callers can register more with
# ``RetentionEngine.register_policy``; re-registering a data_type replaces the
# prior policy.
DEFAULT_POLICIES: tuple[RetentionPolicy, ...] = (
    # SOX §103 / §802: 7-year retention for audit records of public companies.
    RetentionPolicy(
        data_type="audit_logs",
        retention_days=2555,  # 7 years
        action="archive",
        description="SOX 7-year audit-log retention (§103/§802)",
    ),
    # The append-only attestation ledger is the evidence layer (T1 trust-core).
    # It must never be deleted — GDPR erasure is implemented by shredding the
    # per-record encryption keys, not by deleting entries.
    RetentionPolicy(
        data_type="attestation_ledger",
        retention_days=INDEFINITE,
        action="archive",
        description="indefinite — evidence layer; erasure via key shredding",
    ),
    # Agent capability receipts (I1) — keep for SOX window.
    RetentionPolicy(
        data_type="agent_receipts",
        retention_days=2555,
        action="archive",
        description="7-year retention of agent capability receipts",
    ),
    # Eval results churn fast and have low long-term value — 90 days.
    RetentionPolicy(
        data_type="eval_results",
        retention_days=90,
        action="delete",
        description="90-day retention for model eval results",
    ),
    # PII — GDPR default of 1 year; subject-access / erasure requests shorten
    # this per-record via ``apply_tombstone``.
    RetentionPolicy(
        data_type="pii_data",
        retention_days=365,
        action="anonymize",
        description="GDPR PII retention default (1 year); right-to-erasure on request",
    ),
)


class TombstoneError(Exception):
    """Raised when a GDPR tombstone operation cannot be applied."""


@dataclass
class RetentionEngine:
    """Applies retention policies and GDPR right-to-erasure to records.

    The engine is policy-driven: it ships with [DEFAULT_POLICIES] registered,
    and callers add or override policies with [register_policy]. It has no I/O
    of its own — it is a pure in-memory decision layer. The caller is
    responsible for performing the actual delete/anonymize/archive action once
    [check_expired] reports ``True``.

    For GDPR erasure, two mechanisms are provided:

      * [apply_tombstone] — rewrites the sensitive fields of a record dict to
        ``REDACTED`` while preserving the record's structure (the
        append-only ledger stays intact). A ``_tombstone`` marker with the
        erasure timestamp and an HMAC of the original field names is added so
        the tombstone is auditable and tamper-evident.
      * [key_shred] — deletes the encryption key for a record from a
        ``key_store`` (any ``MutableMapping[str, bytes]``), rendering the
        ciphertext permanently unreadable. This is the recommended erasure
        pattern for the attestation ledger: the entry is never deleted, but
        the data it protects becomes cryptographically inaccessible.
    """

    policies: dict[str, RetentionPolicy] = field(default_factory=dict)
    _shred_log: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Pre-load defaults if the caller did not supply an explicit mapping.
        if not self.policies:
            for p in DEFAULT_POLICIES:
                self.policies[p.data_type] = p

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def register_policy(self, policy: RetentionPolicy) -> None:
        """Register (or replace) a retention rule for ``policy.data_type``."""
        self.policies[policy.data_type] = policy

    def get_policy(self, data_type: str) -> RetentionPolicy | None:
        """Return the policy for ``data_type`` or ``None`` if unregistered."""
        return self.policies.get(data_type)

    def has_policy(self, data_type: str) -> bool:
        """Whether a policy exists for ``data_type``."""
        return data_type in self.policies

    # ------------------------------------------------------------------
    # Expiry checking
    # ------------------------------------------------------------------

    def check_expired(self, data_type: str, timestamp: float, *, now: float | None = None) -> bool:
        """Return ``True`` if a record of ``data_type`` written at ``timestamp``
        is past its retention window.

        ``timestamp`` and ``now`` are POSIX epoch seconds (``time.time()``).
        If ``now`` is omitted the current wall-clock time is used. A data type
        with no registered policy is treated as never expiring (fail-closed
        toward retention — we never auto-delete something we don't understand).
        A policy with ``retention_days == INDEFINITE`` also never expires.
        """
        policy = self.policies.get(data_type)
        if policy is None:
            return False
        if policy.retention_days == INDEFINITE:
            return False
        current = time.time() if now is None else now
        age_seconds = current - timestamp
        return age_seconds >= policy.retention_days * _SECONDS_PER_DAY

    def retention_action(self, data_type: str) -> RetentionAction | None:
        """Return the configured action for an expired record, or ``None``."""
        policy = self.policies.get(data_type)
        return None if policy is None else policy.action

    # ------------------------------------------------------------------
    # GDPR right-to-erasure
    # ------------------------------------------------------------------

    def apply_tombstone(
        self,
        record: dict[str, Any],
        fields_to_erase: list[str],
        *,
        now: float | None = None,
        secret: bytes | None = None,
    ) -> dict[str, Any]:
        """Apply GDPR right-to-erasure to ``record``.

        A **tombstone** is an auditable marker that sensitive content has been
        erased while the record's structure is preserved (so the append-only
        attestation ledger stays intact). The erasure:

          * Replaces the value of every field named in ``fields_to_erase`` with
            the sentinel ``REDACTED``. Nested dicts are deep-copied and erased
            recursively (a field path ``"a.b"`` is interpreted literally as a
            key named ``"a.b"``; for nested traversal pass nested dicts and the
            exact key).
          * Records a ``_tombstone`` entry in the returned record containing:
            the erasure timestamp, the list of erased field names, and an HMAC
            over those names (tamper-evident audit trail). If ``secret`` is
            omitted a fixed (non-secret) key is used — supply a real secret in
            production.
          * Leaves all other fields untouched.

        The input ``record`` is **not** mutated; a deep copy is returned.
        """
        if not isinstance(record, dict):
            raise TombstoneError(f"record must be a dict; got {type(record).__name__}")
        if not isinstance(fields_to_erase, list) or any(
            not isinstance(f, str) for f in fields_to_erase
        ):
            raise TombstoneError("fields_to_erase must be a list of strings")

        out = copy.deepcopy(record)
        # De-duplicate while preserving order.
        seen: set[str] = set()
        targets: list[str] = []
        for f in fields_to_erase:
            if f not in seen:
                seen.add(f)
                targets.append(f)

        erased: list[str] = []
        missing: list[str] = []
        for f in targets:
            if self._erase_field(out, f):
                erased.append(f)
            else:
                missing.append(f)

        ts = time.time() if now is None else now
        key = secret if secret is not None else _DEFAULT_TOMBSTONE_HMAC_KEY
        # The HMAC covers the *requested* field list (the caller's erasure
        # intent), so the audit trail is tamper-evident even if some fields
        # were absent. ``fields`` below lists only the fields actually erased.
        mac = hmac.new(key, b"|".join(s.encode("utf-8") for s in targets), hashlib.sha256)
        out["_tombstone"] = {
            "erased": True,
            "erased_at": ts,
            "fields": erased,
            "requested": targets,
            "missing": missing,
            "hmac": mac.hexdigest(),
        }
        return out

    def _erase_field(self, container: dict[str, Any], field_name: str) -> bool:
        """Recursively set ``field_name`` to ``REDACTED`` anywhere it appears.

        Returns ``True`` if at least one occurrence was erased.
        """
        erased_any = False
        if field_name in container:
            container[field_name] = REDACTED
            erased_any = True
        # Recurse into nested dict/list values for any *other* occurrence.
        for v in container.values():
            if isinstance(v, dict):
                erased_any = self._erase_field(v, field_name) or erased_any
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        erased_any = self._erase_field(item, field_name) or erased_any
        return erased_any

    # ------------------------------------------------------------------
    # Cryptographic key shredding
    # ------------------------------------------------------------------

    def key_shred(
        self,
        record_id: str,
        key_store: dict[str, bytes],
        *,
        audit: bool = True,
        now: float | None = None,
    ) -> bool:
        """Shred the encryption key for ``record_id`` in ``key_store``.

        This implements GDPR right-to-erasure for records whose confidentiality
        depends on a per-record encryption key (the recommended pattern for
        AumOS audit records and the attestation ledger). The **ciphertext is
        left in place**; only the key is deleted. The data therefore becomes
        cryptographically inaccessible without altering the append-only ledger
        — satisfying both GDPR's "put beyond use" requirement and the
        tamper-evidence invariant (I-07) that ledger entries are immutable.

        Args:
            record_id: identifier of the record whose key to shred.
            key_store: a mutable mapping (e.g. ``dict``) of ``record_id -> key bytes``.
            audit:     when ``True`` (default) the shred is appended to an
                       in-memory audit log accessible via [shred_log].
            now:       override for the wall-clock timestamp used in the audit log.

        Returns ``True`` if a key was present and shredded, ``False`` if no key
        existed for ``record_id`` (idempotent — a second call returns ``False``).
        """
        if not isinstance(record_id, str) or not record_id:
            raise TombstoneError("record_id must be a non-empty string")
        if not hasattr(key_store, "__delitem__") or not hasattr(key_store, "__contains__"):
            raise TombstoneError("key_store must be a mutable mapping supporting del/contains")

        if record_id not in key_store:
            return False
        # Overwrite the key bytes in memory before deleting (best-effort defence
        # against forensic recovery of freed heap pages — not a guarantee).
        try:
            key_bytes = key_store[record_id]
            if isinstance(key_bytes, bytearray | memoryview):
                _secure_zero(key_bytes)
        except Exception:  # defensive: shredding must not abort on a bad buffer
            pass
        del key_store[record_id]

        if audit:
            ts = time.time() if now is None else now
            self._shred_log.append(
                {
                    "record_id": record_id,
                    "shredded_at": ts,
                    "action": "key_shred",
                }
            )
        return True

    def shred_log(self) -> list[dict[str, Any]]:
        """Return a copy of the in-memory key-shred audit log."""
        return list(self._shred_log)


# Module-level default HMAC key for tombstones. NOT secret — callers must pass
# ``secret=`` to ``apply_tombstone`` in production for a tamper-evident trail.
_DEFAULT_TOMBSTONE_HMAC_KEY = b"warrantor-retention-tombstone-default-hmac-key"


def _secure_zero(buf: bytearray | memoryview) -> None:
    """Best-effort zeroise of a mutable buffer in place."""
    n = len(buf)
    for i in range(n):
        buf[i] = 0
