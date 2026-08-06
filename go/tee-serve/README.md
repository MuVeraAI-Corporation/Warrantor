# aumos tee-serve (C1-4)

TEE-backed model serving sidecar. Runs *inside* the trusted execution environment (Azure
DC-series, AWS Nitro Enclaves, GCP Confidential VMs) and:

1. **Terminates TLS in the TEE** — plaintext never leaves the enclave before being proxied.
2. **Forwards over a Unix Domain Socket** — the only egress channel the enclave exposes for
   inference traffic. No TCP egress.
3. **Wraps every response in an `AttestationEnvelope`** — a signed claim that proves the
   inference ran on attested hardware with a known model digest.
4. **<2ms proxy overhead target** (enforced by CI benchmarks).

## Quickstart (dev)

```bash
# 1. Run a mock inference backend on a Unix socket.
socat UNIX-LISTEN:/tmp/infer.sock,fork TCP:localhost:8080 &

# 2. Start tee-serve (plaintext, mock attestation).
go run ./cmd/tee-serve \
    --addr :8443 \
    --upstream-socket /tmp/infer.sock \
    --model-digest sha256:abcd

# 3. Send a request.
curl -s http://localhost:8443/v1/chat/completions \
    -d '{"model":"m","messages":[]}' | jq
```

## Endpoints

| Method | Path        | Description                                                |
|--------|-------------|------------------------------------------------------------|
| GET    | `/healthz`  | Liveness (never contacts the upstream).                    |
| GET    | `/readyz`   | Readiness — probes the upstream with `HEAD /healthz`.      |
| GET    | `/versionz` | Build info (`component`, `version`, `scheme`).             |
| GET    | `/pubkey`   | Hex Ed25519 public key the proxy signs envelopes with.     |
| any    | `/v1/*`     | Proxied to the upstream; response wrapped in envelope.     |

## `AttestationEnvelope` (v1)

```json
{
  "schema_version": "teeserve.v1",
  "tee_kind": "sev-snp",
  "tee_measurement": "deadbeef...",
  "gpu_model": "H100",
  "gpu_attestation_hex": "cafe...",
  "model_digest": "sha256:abc",
  "response_digest": "sha256:...",
  "upstream_status": 200,
  "proxied_at": "2026-08-05T12:00:00Z",
  "nonce_hex": "00112233445566778899aabbccddeeff",
  "signing_key_hex": "...",
  "signature_hex": "..."
}
```

Clients verify (1) `response_digest` matches the body received, (2) `model_digest` is the
expected one, (3) `tee_measurement` matches the enclave they registered, (4) the Ed25519
signature over the canonical bytes verifies against `signing_key_hex`.

## References

- RFC `docs/rfcs/C1-4-tee-serve.md`
- Depends on C1-3 `attesta-flow` (production attestation provider).
- Depends on C1-1 `nvtrust-bridge` for `gpu_attestation_hex`.
