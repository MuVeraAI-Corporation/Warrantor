# Wave-4 Integration Guide — Inference Stack

> N1 (proxy), N2 (backend bridge), N3 (gateway), N4 (multi-tenant GPU) compose into the
> Warrantor inference stack — OpenAI-compatible, backend-agnostic, multi-tenant, attested.

## The inference request flow

```
Client ──POST /v1/chat/completions──▶ N3 inference-proxy
                                        │
                                        ▼
                                   ┌─ auth (SPIFFE/API-key)
                                   ├─ rate-limit (per-identity token bucket)
                                   ├─ prompt-filter (injection / PII / policy)
                                   ├─ cache (exact-match in v1.0)
                                   ▼
                                N1 open-serve-kit (Go HTTP proxy)
                                        │
                                        ▼
                                   N2 bridge-rt (selects backend)
                                        │
                            ┌───────────┼───────────┐
                            ▼           ▼           ▼
                       TRT-LLM       vLLM       Ollama
                       (MIG slice)  (MPS)       (none)
                            │
                            ▼
                       N4 tenant-guard ensures the GPU slice the
                       backend runs on belongs to the caller's tenant,
                       with a valid AAE bound to it
```

## Per-component wire-off

| Wire | Producer → Consumer | Format |
|---|---|---|
| Client → N3 | HTTP POST /v1/chat/completions (OpenAI shape) | JSON |
| N3 → N1 | backend closure (in v1.0) or HTTP call (production) | function / HTTP |
| N1 → N2 | `GenerateRequest` | in-process call |
| N2 → backend | backend-native (HTTP for vLLM/Triton; TRT-LLM in-process) | varies |
| N4 → N1 | GPU allocation: the backend reads its assigned GPU from the Allocation | k8s env / GPU id |

## Key NVIDIA compatibility

N2 bridge-rt detects TRT-LLM version at runtime and adapts:
- **< 0.16**: no `sampler_type` arg
- **>= 0.16**: injects `sampler_type=trtllm` (the new default)

This is documented in `docs/cross-cutting/11-nvidia-compatibility-matrix.md` (referenced).

## Reproducible demo

```bash
# 1. Start N1 with the Mock backend.
go run ./go/open-serve-kit/cmd/open-serve-kit -addr=:8443 -backend=mock

# 2. Curl the OpenAI-compatible endpoint.
curl -s -X POST http://localhost:8443/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"m","messages":[{"role":"user","content":"hi"}]}'

# 3. Probe N2 backend availability.
bridge-rt probe --json

# 4. Generate via N2.
bridge-rt generate --model m --prompt hi --force mock
```
