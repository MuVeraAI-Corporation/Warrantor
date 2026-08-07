# aumos-agent

A unified Python SDK that gives any coding agent (Claude Code custom tools, OpenAI Codex
scripts, Cursor rules, LangChain agents, or a hand-rolled script) the **AumOS security
primitives** as first-class Python objects.

The headline feature is the **`@agent.action` decorator**, which wraps any function with the
full AumOS security envelope — identity, preflight, credential brokering, signed receipts, and
containment — in one line.

## Install

```bash
cd python/aumos_agent
pip install -e .            # core (stdlib HTTP via urllib)
pip install -e '.[http]'    # preferred: uses httpx when available
pip install -e '.[dev]'     # + pytest, ruff for development
```

Requires Python 3.11+.

## Quick start

```python
from aumos_agent import AumOS

# standalone = mock implementations, zero external services. Perfect for dev & dry-runs.
agent = AumOS(
    mode="standalone",
    agent_identity_url="http://localhost:8441",  # I1 agent-identity
    # trust_core_url=None  → uses the `trust-core` CLI subprocess
    # flight_recorder_url=None
)

# Decorate any function. The wrapper does identity, preflight, credential brokering,
# emits a signed receipt BEFORE the action commits (invariant I-07), records evidence,
# and triggers the kill-switch on exception (containment).
@agent.action(tool="github.create_pr", side_effect="write")
def create_pull_request(repo: str, title: str, body: str):
    # your agent's actual logic here
    return {"pr_number": 42, "url": f"https://github.com/{repo}/pull/42"}

result = create_pull_request("aumos/aumos", "feat: x", "body")
# result is the wrapped function's return value.
# The structured ActionResult is on the function attribute:
ar = create_pull_request.action_result
print(ar.receipt.receipt_id)   # aar-...
print(ar.outcome)              # 'success'
print(agent.evidence)          # full append-only evidence trail
```

## What the decorator does

Per call, in order:

1. **Issues/verifies an agent identity** (I1 agent-identity).
2. **Runs pre-flight sandbox checks** (R2 eval-guard). If `fail_closed=True` (default) and
   preflight denies, raises `ActionBlocked` and the wrapped function never runs (invariant I-09).
3. **Brokers scoped credentials** (R4 credential-vault) — scans the JSON-serialized args for
   leaked secrets; findings are attached to the preflight result.
4. **Emits an Agent Action Receipt *before* the action commits** (E1 flight-recorder,
   invariant I-07).
5. **Records the action** in `agent.evidence`.
6. **On exception**: emits a `failure` receipt and (if `auto_kill_on_error=True`) triggers the
   R3 kill-switch, then raises `ContainmentTriggered`.

## Manual API

Every primitive is also available as a direct method:

```python
agent.sign(data)                        → str          # Ed25519 hex signature (T1)
agent.verify(data, signature, key)      → bool         # (T1)
agent.emit_receipt(actor, tool, outcome)→ Receipt      # (E1) — receipt_id + signature
agent.verify_receipt(receipt_id)        → dict
agent.issue_identity(subject)           → dict         # svid, capability_jti, verifying_key
agent.verify_identity(svid)             → dict         # {valid, subject, reason?}
agent.revoke_identity(jti)              → dict
agent.check_attestation(nonce=...)      → dict         # (C1-1)
agent.run_preflight(tool, side_effect=..)→ dict        # (R2) — {allowed, reason}
agent.kill(reason="behavioral_anomaly") → dict         # (R3) — containment
agent.scan_secrets(text)                → list[Finding]# (R4)
agent.compliance_report(scope="soc2")   → dict         # (X1)
agent.install("flight-recorder")        → dict         # (X1)
agent.generate_sbom("llama-3-8b")       → dict         # (S4) — CycloneDX
agent.run_eval("model://x", pipeline_yaml) → dict      # (A1) — results + VEB
```

## Two modes

| Mode | Behavior |
|---|---|
| `standalone` (default) | All primitives return deterministic mock responses. Zero network, zero CLIs. For development, tests, demos, dry-runs. |
| `connected` | Primitives issue real HTTP calls (I1, E1, C1-1, S4, A1, R2, R3, R4) and shell out to CLIs (`trust-core`, `defstack`). **On connection failure, each call degrades gracefully** to the mock and sets `degraded: True` — your agent always gets an answer. |

```python
agent = AumOS(
    mode="connected",
    agent_identity_url="http://localhost:8441",
    flight_recorder_url="http://localhost:8445",
    # ... other service URLs
)
```

## Fail-closed behavior

```python
agent = AumOS(fail_closed=True)   # default

@agent.action(tool="db.drop_table", side_effect="destructive")
def drop_table():
    ...

drop_table()   # raises ActionBlocked — destructive needs approval (invariant I-08)
```

Consequential side-effect classes (`financial`, `destructive`, `physical`) are blocked by default
in standalone preflight because they require explicit human approval (invariant I-08). Set
`fail_closed=False` to observe-but-proceed (useful for read-only inspection).

## Exception handling

```python
@agent.action(tool="x.write", side_effect="write")
def boom():
    raise RuntimeError("kaboom")

boom()   # raises ContainmentTriggered — kill-switch fired, failure receipt recorded
```

The failure path always emits a `failure` receipt. With `auto_kill_on_error=True` (default) the
R3 kill-switch fires before re-raising. Set it to `False` to re-raise the original exception
unchanged (the failure receipt is still recorded).

## CLI

```bash
aumos-agent status
aumos-agent issue spiffe://aumos.dev/agent/coding-1
aumos-agent scan-secrets --text "token=ghp_..."
echo "AKIAIOSFODNN7EXAMPLE" | aumos-agent scan-secrets
aumos-agent --version
```

## Coding-agent integrations

### Claude Code (custom tool)

```python
# .claude/tools/aumos.py
from aumos_agent import AumOS
agent = AumOS(mode="standalone")

def aumos_scan(text: str) -> dict:
    findings = agent.scan_secrets(text)
    return {"count": len(findings), "findings": [f.as_dict() for f in findings]}
```

### OpenAI Codex script

```python
from aumos_agent import AumOS
agent = AumOS(mode="connected", agent_identity_url="http://localhost:8441")

@agent.action(tool="ci.deploy", side_effect="write")
def deploy(service: str):
    ...  # deployment logic
```

### LangChain tool wrapper

```python
from langchain_core.tools import tool
from aumos_agent import AumOS

aumos = AumOS(mode="standalone")

@tool
def safe_sign(data: str) -> str:
    """Sign data with the AumOS trust-core."""
    return aumos.sign(data)
```

## Design principles

- **Zero-friction**: `@agent.action` wraps any function with full AumOS security.
- **Graceful degradation**: standalone mocks; connected calls fall back to mocks on failure.
- **Coding-agent friendly**: importable from notebooks, scripts, rules, or tool wrappers.
- **Evidence-first**: every decorated action produces a verifiable receipt (P2 AAR).
- **Fail-closed**: a failing security check blocks the action (invariant I-09).

## Test

```bash
cd python/aumos_agent
pytest                 # 56 tests
ruff check src/ tests  # clean
```

## License

Apache-2.0.
