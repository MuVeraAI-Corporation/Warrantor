# warrantor-notary (Python)

**W1 Notary — third-party Verify path for WAR receipts.**

The verdict function (spec 11) is implemented **once**, in Rust (`warrantor-notary`). This package
does NOT re-implement any gate (spec 11 §1: *no security invariant may have two authoritative
implementations*). It does the thing the README calls &ldquo;the test that matters&rdquo;: verify a
receipt the Rust notary issued, with no privileged access and no shared secret, and independently
recompute the authority intersection to confirm the receipt's claim.

## Spec

- [`specs/warrantor-v4/02-notary-api.md`](../../specs/warrantor-v4/02-notary-api.md) — the Notary API
- [`specs/warrantor-v4/11-verdict-function.md`](../../specs/warrantor-v4/11-verdict-function.md) — the 9-gate verdict (Rust-only)

## Install (dev)

```bash
pip install -e .[dev]
```

## Use

```python
import json
import warrantor_notary as wn

# A third party receives a receipt issued by the Rust notary.
receipt = json.load(open("receipt.json"))

# 1. Verify the signature — no privileged access, no shared secret.
wn.verify_receipt(receipt)   # raises NotaryError on failure

# 2. Spot-check the authority intersection (the README test).
recomputed = wn.effective_capabilities(actor_dict)
assert recomputed == receipt["body"]["verdict"]["effective_capabilities"]
```

## Interop

The Rust example `issue_vector_receipts` produces a bundle of 16 signed receipts (one per
conformance vector); this package's `verify_bundle` verifies all of them + recomputes the
intersection for every Allow. See `tests/test_notary.py::test_interop_rust_bundle`.

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```
