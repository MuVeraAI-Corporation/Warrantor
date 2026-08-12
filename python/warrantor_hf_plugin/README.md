# warrantor-hf-plugin

Sign a model on upload, verify it on download — with the provenance written **inside the
safetensors file**, not alongside it.

```bash
pip install warrantor-hf-plugin
```

No runtime dependencies. Python 3.11+.

## Why the header, and not a sidecar file

The usual approach ships a `model.sig` next to the weights. It works until the file moves — and
model files move constantly: mirrored to an internal bucket, pulled through a proxy, copied into a
container image, attached to a ticket. Every one of those hops is somewhere the signature can be
dropped, and a missing sidecar is indistinguishable from a model that was never signed.

This writes a `__provenance__` block into the safetensors header instead. The header is part of the
file, so provenance survives any transport that preserves the bytes. A model that arrives at all
arrives with its signature.

## Use

```python
from warrantor_hf_plugin import sign_model_for_upload, verify_model_on_download

# Before pushing to the Hub
block = sign_model_for_upload(
    "model.safetensors",
    signer="did:web:muveraai.com",
)

# After pulling, before loading
result = verify_model_on_download("model.safetensors")
if not result.verified:
    raise RuntimeError(f"refusing to load: {result.reason}")
```

`VerificationResult` carries `verified`, `signer`, `signed_at`, `data_digest` and a `reason` — the
last so a failure tells you *what* failed rather than just returning `False`. A digest mismatch and
an absent signature are different problems and want different responses.

The signature covers the tensor data, so a modified weight fails verification even though the
header still parses and the file still loads.

## Verify a directory

```python
from warrantor_hf_plugin import batch_verify

for result in batch_verify("./models"):
    print(result.verified, result.signer, result.reason)
```

## Hooking into a training run

```python
from warrantor_hf_plugin import HFCallback
```

`HFCallback` signs checkpoints as they are written, so the provenance chain starts at training
rather than being applied retroactively at publish time — by which point nobody can say what the
artifact passed through.

## Keys

`sign_model_for_upload` accepts `signing_key_hex`. If you omit it a key is generated, which is
convenient for a first run and wrong for anything you intend to verify later — a signature is only
worth as much as the continuity of the key behind it. Pass a key you keep.

## License

Apache-2.0
