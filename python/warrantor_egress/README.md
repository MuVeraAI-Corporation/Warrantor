# warrantor-egress (Python)

**W5 Egress broker — Python verify path for egress decision receipts.**

The decision engine (spec 08) is Rust-only. This package verifies the signed receipts the Rust
broker issues, so any third party can confirm an egress decision independently.

## Spec

[`specs/warrantor-v4/08-egress-broker.md`](../../specs/warrantor-v4/08-egress-broker.md)

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```
