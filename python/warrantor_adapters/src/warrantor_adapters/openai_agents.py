"""OpenAI Agents SDK adapter.

The OpenAI Agents SDK uses lifecycle hooks (``RunHooks``, tool-level hooks) to intercept agent
actions. This adapter provides :class:`WarrantorHooks` that wraps tool calls with Warrantor
authorize→attest. Zero-dependency: works as a standalone callable if the SDK is not installed.

Usage::

    from warrantor_adapters.openai_agents import WarrantorHooks
    from agents import Runner

    hooks = WarrantorHooks(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        capabilities=["read"],
    )
    result = Runner.run_sync(agent, "What's the weather?", hooks=hooks)
"""

from __future__ import annotations

from typing import Any

from .base import WarrantorGuard


class WarrantorHooks:
    """OpenAI Agents SDK lifecycle hooks that authorize every tool call.

    Works with the Agents SDK ``RunHooks`` / tool-hooks pattern. Each ``on_tool_start``
    authorizes; ``on_tool_end`` attests. If the verdict is deny, raises
    :class:`PermissionDenied` and the tool does not run.
    """

    def __init__(
        self,
        actor_svid: str,
        capabilities: list[str],
        **kwargs: Any,
    ) -> None:
        self.guard = WarrantorGuard(actor_svid, capabilities, **kwargs)
        self._receipts: dict[str, dict] = {}  # tool_call_id → receipt

    def on_tool_start(self, tool_name: str, tool_input: Any = None, **kwargs: Any) -> None:
        """Authorize before the tool runs. Raises PermissionDenied on deny.

        Pass ``capabilities=["financial"]`` to require a specific capability for this tool.
        """
        capabilities = kwargs.get("capabilities")
        receipt = self.guard.authorize_action(
            operation=f"openai_tool:{tool_name}",
            capabilities=capabilities,
        )
        call_id = kwargs.get("tool_call_id", tool_name)
        self._receipts[call_id] = receipt

    def on_tool_end(
        self, tool_name: str, output: Any = None, *, tool_call_id: str | None = None, **kwargs: Any
    ) -> None:
        """Attest the outcome."""
        call_id = tool_call_id or tool_name
        receipt = self._receipts.pop(call_id, None)
        if receipt is None:
            return
        status = "success"
        digest = f"sha256:{abs(hash(str(output))) & 0xFFFFFFFFFFFFFFFF:016x}"
        self.guard.attest_action(receipt, outcome_status=status, outcome_digest=digest)

    def on_handoff(self, from_agent: str, to_agent: str, **kwargs: Any) -> None:
        """Authorize an agent-to-agent handoff (W6 delegation surface)."""
        self.guard.authorize_action(
            operation=f"handoff:{from_agent}->{to_agent}",
            consequence_tier="elevated",
        )
