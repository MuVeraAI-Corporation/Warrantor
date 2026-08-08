# aumos-retention

AumOS data retention policy engine and GDPR right-to-erasure (tombstone) support.

This module implements the **M1 fix**: a declarative data-retention layer plus
cryptographically-sound GDPR right-to-erasure that preserves the append-only
attestation ledger while rendering sensitive content permanently inaccessible.

## What it does

- **Retention policies** — map a data type to a retention window (days) and an
  expiry action (`delete` / `anonymize` / `archive`).
- **Expiry checking** — given a data type and a timestamp, decide whether the
  data is past its retention window.
- **GDPR right-to-erasure (tombstone)** — replace the sensitive fields of a
  record with `REDACTED` while preserving the record's structure. A
  tamper-evident `_tombstone` marker (with an HMAC over the erased field names)
  is written into the record so the erasure is auditable.
- **Cryptographic key shredding** — for records whose confidentiality depends on
  a per-record encryption key (the recommended pattern for AumOS audit records
  and the `attestation_ledger`), delete the key. The ciphertext is left in
  place; only the key is gone. The data becomes cryptographically inaccessible
  without altering the append-only ledger — satisfying both GDPR's "put beyond
  use" and AumOS's tamper-evidence invariant (I-07).

## Default policies

| data type            | retention | action     | rationale                                  |
| -------------------- | --------- | ---------- | ------------------------------------------ |
| `audit_logs`         | 2555 days | `archive`  | SOX §103/§802 7-year retention             |
| `attestation_ledger` | indefinite| `archive`  | evidence layer; erasure via key shredding  |
| `agent_receipts`     | 2555 days | `archive`  | 7-year retention of I1 capability receipts |
| `eval_results`       | 90 days   | `delete`   | high churn, low long-term value            |
| `pii_data`           | 365 days  | `anonymize`| GDPR default; subject requests shorten it  |

## Usage

```python
from aumos_retention import RetentionEngine, RetentionPolicy

engine = RetentionEngine()                       # pre-loaded with defaults
engine.register_policy(
    RetentionPolicy("custom_log", retention_days=30, action="delete")
)

# Retention check
if engine.check_expired("audit_logs", old_record_timestamp):
    apply_action(engine.retention_action("audit_logs"), old_record)

# GDPR right-to-erasure (tombstone)
redacted = engine.apply_tombstone(
    record,
    fields_to_erase=["user_email", "ssn"],
    secret=b"production-hmac-secret",
)

# Cryptographic key shredding (attestation ledger)
key_store = {"rec-123": b"...per-record-encryption-key..."}
assert engine.key_shred("rec-123", key_store)   # ciphertext stays, key is gone
```

## Design notes

- **Fail-closed retention.** A data type with no registered policy is treated as
  never expiring — we never auto-delete something we don't understand.
- **`INDEFINITE` ≠ "no policy".** Indefinite-retention data types (e.g. the
  attestation ledger) still have an explicit policy; they just never time out.
- **The ledger is never mutated by erasure.** `apply_tombstone` deep-copies the
  input record and returns a new dict; the original is untouched. The
  caller decides where to persist the tombstoned form.
- **Key shredding overwrites then deletes.** Where the key buffer is mutable
  (`bytearray`/`memoryview`) it is best-effort zeroised before removal. This is
  not a forensic guarantee — use a KMS-backed key store for production.

## Running the tests

```bash
pip install -e '.[dev]'
pytest
```
