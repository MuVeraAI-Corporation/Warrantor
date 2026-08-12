# warrantor-retrieval (Python)

**W7 Retrieval broker — Python verify path for retrieval decision receipts (RAG security).**

The decision engine is Rust-only. This package verifies the signed receipts the Rust broker issues.

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```
