# warrantor

**The one-import SDK for verifiable agent authority.**

Self-contained — only depends on `cryptography`. Wraps the notary verdict (9 gates), evidence
envelope (pre→post commit chaining), and agent manifest (`agent.yaml`) into one ergonomic API.

## Install (dev)

```bash
pip install -e .[dev]
```

## Quick start

```python
import warrantor

client = warrantor.Client()

# Authorize → verdict + signed pre_commit receipt
result = client.authorize(
    actor_svid="spiffe://yourcorp/agents/bot-1",
    actor_capabilities=["read", "write"],
    operation_capabilities=["read"],
    consequence_tier="routine",
    scope="prod",
)
assert result.verdict == "allow"

# Attest → signed post_commit receipt (chains to pre_commit)
post = client.attest(result.receipt, outcome_status="success", outcome_digest="sha256:abc")

# Verify — any third party, no privileged access
warrantor.verify_chain(result.receipt, post)

# Agent manifests
manifest = client.create_manifest(
    name="my-agent",
    identity="spiffe://yourcorp/agents/my-agent",
    capabilities=["read"],
    policy_refs=["pol-1"],
    enforcement_mode="observed",
)
warrantor.Client.verify_manifest(manifest)
```

## API

| Method | Description |
|---|---|
| `Client()` | Create a client (generates an Ed25519 keypair). |
| `.authorize(...)` | Run the 9-gate verdict + issue a signed pre_commit receipt. |
| `.attest(pre, ...)` | Issue a signed post_commit receipt chaining to the pre_commit. |
| `.create_manifest(...)` | Build + sign an agent manifest (agent.yaml). |
| `verify_receipt(r)` | Verify a single WAR receipt's Ed25519 signature. |
| `verify_chain(pre, post)` | Verify a pre→post chain (commit gate I-07 + signatures). |
| `Client.verify_manifest(signed)` | Verify a signed agent manifest. |
| `Client.parse_manifest(json)` | Parse + validate an agent.yaml JSON string. |

## Test

```bash
PYTHONPATH=src pytest tests/ -v
```
