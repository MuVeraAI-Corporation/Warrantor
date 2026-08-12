# warrantor-evidence (Python)

**W2 Evidence envelope — third-party Verify path for WAR receipts.**

The pre_commit→post_commit chaining (spec 01, WAR v2.0). Signing and the commit gate are Rust-only
(spec 01 §4: *only the Rust trusted core signs*); this package verifies chains with no privileged
access — any third party can confirm a chain is well-formed, signatures authentic, the authority
intersection recomputes (I-02), and the commit gate holds (I-07).

## Spec

[`specs/warrantor-v4/01-war-receipt.md`](../../specs/warrantor-v4/01-war-receipt.md)

## Install (dev)

```bash
pip install -e .[dev]
```

## Use

```python
import json
import warrantor_evidence as we

bundle = json.load(open("chain.json"))
we.verify_chain(bundle["pre_commit"], bundle["post_commit"])  # raises EvidenceError on failure
```

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```
