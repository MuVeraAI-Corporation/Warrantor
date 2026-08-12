# warrantor-langchain

**LangChain / LangGraph harness adapter** for Warrantor. Wraps a LangChain agent
so that:

1. Every LLM and tool action is recorded as an **AAR** (Agent Action Record —
   P2 / E1 flight recorder).
2. Every output is scanned for **secrets** (R4) and can **trigger the
   kill-switch** (R3) when a secret is exposed.
3. Tool calls are gated by an **AAE** (Action Enforcer) permission check.

## Zero-dependency design

The adapter is intentionally **zero-dependency**:

- If LangChain is installed, `WarrantorCallback` is *also* a real
  `langchain_core.callbacks.BaseCallbackHandler` subclass, so it can be passed
  to any LangChain runner.
- If LangChain is **not** installed, the same class still works against any
  caller that respects the LangChain callback handler shape
  (`on_llm_start`, `on_tool_start`, `on_tool_end`, ...). This makes it useful
  in constrained environments and unit-testable without the heavy
  `langchain` dependency.

Use `has_langchain()` to detect which mode you are in.

## Components

- `WarrantorCallback` — LangChain-compatible callback handler that records every
  LLM / tool / chain action as an `AAR`, scans outputs for secrets, and
  invokes a configurable `kill_switch` when a secret is exposed.
- `WarrantorTool` — callable wrapper that duck-types as a LangChain `Tool` and
  refuses to run unless the configured permission check passes (raises
  `PermissionDenied`).
- `wrap_agent(agent, identity, side_effect_class, ...)` — attaches an
  `WarrantorCallback` to a LangChain-style agent and returns a `SecuredAgent`.
- `scan_for_secrets(text)` — standalone secret scanner.

## Usage

```python
from warrantor_langchain import WarrantorCallback, WarrantorTool, wrap_agent

callback = WarrantorCallback(
    identity="alice",
    kill_switch=lambda aar: print(f"KILL: {aar.secret_findings}"),
)

# Attach to any object exposing a `callbacks` attribute:
secured = wrap_agent(agent, identity="alice", side_effect_class="write")
secured.run("hello")

# Or gate a tool:
tool = WarrantorTool(
    name="calc",
    description="calculator",
    func=lambda x: x + 1,
    permission="compute",
    identity="alice",
    permission_check=lambda ident, perm: ident == "alice",
)
tool(5)  # -> 6
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
