# warrantor-adapters

**D2 — Framework adapters for Warrantor.** One-line drop-ins for LangChain, OpenAI Agents SDK,
and Anthropic SDK that add verifiable authority + evidence to every agent action via the
`warrantor` SDK.

## Install (dev)

```bash
pip install -e .[dev]
```

## LangChain / LangGraph

```python
from warrantor_adapters.langchain import WarrantorCallback

agent.invoke(input, config={"callbacks": [WarrantorCallback(
    actor_svid="spiffe://yourcorp/agents/bot-1",
    capabilities=["read", "write"],
)]})
```

## OpenAI Agents SDK

```python
from warrantor_adapters.openai_agents import WarrantorHooks

hooks = WarrantorHooks(
    actor_svid="spiffe://yourcorp/agents/bot-1",
    capabilities=["read"],
)
result = Runner.run_sync(agent, "query", hooks=hooks)
```

## Anthropic SDK

```python
from warrantor_adapters.anthropic_sdk import warrantor_guard, warrantor_tool

# Context manager
with warrantor_guard(actor_svid="spiffe://...", capabilities=["read"]) as g:
    result = my_tool(args)

# Decorator
@warrantor_tool(actor_svid="spiffe://...", capabilities=["read"])
def get_data(query: str) -> str:
    return f"data for {query}"
```

## How it works

Every adapter calls `Client.authorize()` **before** the action (the 9-gate verdict) and
`Client.attest()` **after** (the post_commit receipt). A `deny` verdict raises
`PermissionDenied` — the action does not execute. The resulting pre_commit→post_commit chain is
verifiable by any third party via `warrantor.verify_chain()`.

## Test

```bash
PYTHONPATH="src;../warrantor/src" pytest tests/ -v
```
