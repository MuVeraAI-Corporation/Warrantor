# cuda-gram (C1-2)

High-level GPU attestation SDK. Wave-1 scaffolding ships a pure-Python `MockBackend`; the real
implementation (task 02) calls the C1-1 Rust core (`aumos-nvtrust-bridge`) via PyO3.

See [`docs/rfcs/C1-2-cuda-gram.md`](../../docs/rfcs/C1-2-cuda-gram.md).

## Dev

```bash
cd python/cuda_gram
pip install -e ".[dev]"
pytest -q
```
