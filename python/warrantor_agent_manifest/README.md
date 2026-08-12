# warrantor-agent-manifest (Python)

**M1 — the OpenAPI for agents.** A declarative, signed, receipted description of what an agent
*is*: identity, the side-effect classes it may use, the policies that bind it, the model/tools/data
it depends on, the runtime attestation it requires, and its enforcement mode. An agent without a
valid signed manifest cannot obtain authority.

Companion to the Rust crate [`warrantor-agent-manifest`](../../rust/agent-manifest). Both
implementations pass the same conformance vectors at
[`testvectors/agent-manifest/vectors.json`](../../testvectors/agent-manifest/vectors.json) and
produce byte-identical canonical-JSON, so an Ed25519 signature computed in one language verifies
in the other (cross-language interop verified).

## Spec

[`specs/warrantor-v4/16-agent-manifest.md`](../../specs/warrantor-v4/16-agent-manifest.md) +
[`16-agent-manifest.schema.json`](../../specs/warrantor-v4/16-agent-manifest.schema.json).

## Install (dev)

```bash
pip install -e .[dev]
```

## Use

```python
import json
import warrantor_agent_manifest as am

# 1. Validate an agent.yaml (loaded as JSON)
manifest = am.parse_and_validate(json.dumps({
    "apiVersion": "agent.warrantor.io/v1",
    "kind": "AgentManifest",
    "name": "payments-bot-3",
    "identity": "spiffe://yourcorp/agents/payments-bot-3",
    "capabilities": ["read", "write", "financial"],
    "policy_refs": ["pol_44"],
    "enforcement_mode": "mediated",
}))

# 2. Issue: sign with the manifest issuer's Ed25519 key
priv, _ = am.generate_keypair()   # production: load from KMS/HSM
signed = am.sign(manifest, priv, "issuer-key-2026-01",
                 issued_at="2026-08-11T20:00:00Z",
                 issuer="spiffe://yourcorp/authority/manifest-issuer",
                 expires_at="2027-08-11T20:00:00Z")

# 3. Verify (any third party, no privileged access)
am.verify(signed)   # raises ManifestError on any failure

# 4. The manifest digest goes into every receipt the agent emits
print(am.digest_hex(manifest))   # sha256 of canonical(manifest)
```

## Error model

`ManifestError` carries a stable `.code` (matching the Rust crate and the conformance vectors) and
`.field` (the offending field, where applicable):

| code | meaning |
|---|---|
| `MALFORMED_JSON` / `NOT_AN_OBJECT` | the input is not a JSON object |
| `MISSING_REQUIRED_FIELD` | one of the 7 required fields is absent |
| `UNEXPECTED_FIELD` | a field not in the schema (additionalProperties: false) |
| `INVALID_API_VERSION` / `INVALID_KIND` | the constant fields are wrong |
| `INVALID_IDENTITY` | identity is not a `spiffe://` URI |
| `EMPTY_CAPABILITIES` / `INVALID_CAPABILITY` | capabilities empty or off the I-08 ladder |
| `EMPTY_POLICY_REFS` | policy_refs empty |
| `INVALID_ENFORCEMENT_MODE` | not `observed` or `mediated` |
| `INVALID_VERSION` | version present but not semver |
| `INVALID_MODEL_DIGEST` | dependencies.model does not match the digest pattern |
| `SIGNATURE` / `SIGNATURE_ENVELOPE` | the Ed25519 signature or envelope is invalid |

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```

15 tests pass: 13 unit + 2 conformance (loading all 13 shared vectors).
