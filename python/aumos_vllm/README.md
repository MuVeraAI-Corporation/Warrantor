# aumos-vllm

**Attested vLLM serving plugin** for AumOS. Wraps a
[vLLM](https://github.com/vllm-project/vllm) OpenAI-compatible server with
AumOS attestation checks so that downstream clients can refuse to talk to an
un-attested serving instance.

## Run modes

| Mode         | Behaviour                                                                 |
| ------------ | ------------------------------------------------------------------------- |
| `mock`       | No real subprocess. Returns synthetic responses and a synthetic, digested attestation envelope. Use in tests and on hosts without a GPU. |
| `standalone` | Spawns `python -m vllm.entrypoints.openai.api_server` as a subprocess. Requires `vllm` to be importable on the host. |

## Attestation envelope

`get_attestation_envelope()` returns an `AttestationEnvelope` containing:

- `model_path` — the model the server is serving.
- `quote` / `report_data` / `measurement` — the TEE quote and report data
  (in mock mode, a deterministic synthetic value).
- `backend` — `"mock"`, `"nvidia-cc"`, `"sev-snp"`, `"tdx"`, ...
- `digest` — `sha256:` of `model_path + report_data` so the envelope is
  reproducible per instance.
- `verified` — whether `_verify_envelope` accepted it.

For real backends, override the quote-collection step to integrate the
platform verifier (NVIDIA Attestation SDK, AMD SEV-SNP, Intel TDX).

## Health model

`health_check()` returns:

- `HEALTHY` — server up **and** attestation OK (when required).
- `UNHEALTHY` — server process down or HTTP probe failed.
- `ATTESTATION_FAILED` — server up but attestation required and missing/invalid.
- `NOT_STARTED` — `start()` was never called.

## Usage

```python
from aumos_vllm import AttestedVLLMServer

with AttestedVLLMServer(mode="mock") as server:
    server.start("/models/llama-3", gpu_attestation_required=True)
    assert server.health_check().value == "healthy"
    envelope = server.get_attestation_envelope()
    print(envelope.digest)

# Standalone mode (requires vllm installed + GPU):
# server = AttestedVLLMServer(mode="standalone", attestation_backend="nvidia-cc")
# server.start("/models/llama-3", gpu_attestation_required=True)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
