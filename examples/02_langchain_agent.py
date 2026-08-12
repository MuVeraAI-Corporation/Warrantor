"""Recipe 2 — Instrument a LangChain agent with Warrantor authority.

Every tool call the agent makes runs through the 9-gate verdict, produces a signed evidence
chain, and a deny verdict blocks the tool from executing. One line of setup.

    from warrantor_adapters.langchain import WarrantorCallback
    agent.invoke(input, config={"callbacks": [WarrantorCallback(...)]})
"""

from __future__ import annotations

import os
import sys

# Ensure the SDK + adapters are importable in the monorepo.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _pkg in ("warrantor", "warrantor_adapters"):
    _src = os.path.join(_ROOT, "python", _pkg, "src")
    if os.path.isdir(_src) and _src not in sys.path:
        sys.path.insert(0, _src)

import warrantor
from warrantor_adapters.langchain import WarrantorCallback
from warrantor_adapters.base import PermissionDenied


def main() -> None:
    # Create the callback — this is the ONE LINE a LangChain developer adds.
    callback = WarrantorCallback(
        actor_svid="spiffe://yourcorp/agents/research-bot",
        capabilities=["read", "write"],
    )

    # Simulate a tool call that IS authorized.
    print("=== Authorized tool call ===")
    callback.on_tool_start(serialized={"name": "search_docs"}, input_str="what is RAG?")
    callback.on_tool_end(output="RAG = Retrieval-Augmented Generation")
    print("✓ search_docs: authorized + attested.")

    # Simulate a tool call that is DENIED (requires "financial" — not in the agent's capabilities).
    print("\n=== Denied tool call ===")
    try:
        callback.guard.authorize_action(operation="charge_card", capabilities=["financial"])
    except PermissionDenied as e:
        print(f"✗ charge_card DENIED at gate: {e.gate}")
        print("  The tool did not execute. The deny is receipted.")


if __name__ == "__main__":
    main()
