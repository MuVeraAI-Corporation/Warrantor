"""D2 Framework adapters for Warrantor — one-line drop-ins.

Wraps the ``warrantor`` SDK into framework-specific callback handlers so a developer adds
verifiable authority + evidence to their agent in one line:

    # LangChain
    from warrantor_adapters.langchain import WarrantorCallback
    agent.invoke(input, config={"callbacks": [WarrantorCallback(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        capabilities=["read", "write"],
    )]})

    # OpenAI Agents SDK
    from warrantor_adapters.openai_agents import WarrantorHooks
    runner = Runner_hooks(..., hooks=WarrantorHooks(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        capabilities=["read"],
    ))

    # Anthropic SDK (context manager)
    from warrantor_adapters.anthropic_sdk import warrantor_guard
    with warrantor_guard(actor_svid="spiffe://yourcorp/agents/bot-1", capabilities=["read"]):
        response = client.messages.create(...)

Each adapter calls ``Client.authorize()`` BEFORE the action and ``Client.attest()`` AFTER,
producing a signed pre_commit→post_commit evidence chain. A ``deny`` verdict raises
:class:`PermissionDenied` — the action does not execute.
"""

from __future__ import annotations

import os
import sys

# Monorepo: ensure the warrantor SDK is importable. In production (pip install), it's a real dep.
_SDK_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "warrantor", "src")
if os.path.isdir(_SDK_SRC) and _SDK_SRC not in sys.path:
    sys.path.insert(0, _SDK_SRC)

import warrantor  # noqa: E402

__all__ = ["PermissionDenied", "WarrantorGuard"]


class PermissionDenied(Exception):
    """Raised when the Warrantor verdict is deny. The action MUST NOT proceed."""

    def __init__(self, gate: str, message: str = "") -> None:
        super().__init__(message or f"Warrantor denied at gate: {gate}")
        self.gate = gate


class WarrantorGuard:
    """The shared guard logic all framework adapters wrap.

    Holds a :class:`warrantor.Client` and provides ``authorize_action`` / ``attest_action``
    methods that the framework-specific adapters call from their hooks.
    """

    def __init__(
        self,
        actor_svid: str,
        capabilities: list[str],
        *,
        client: warrantor.Client | None = None,
        consequence_tier: str = "routine",
        scope: str = "default",
    ) -> None:
        self._client = client or warrantor.Client()
        self.actor_svid = actor_svid
        self.capabilities = capabilities
        self.default_tier = consequence_tier
        self.default_scope = scope
        self._pending: dict[str, dict] = {}  # action_id → pre_commit receipt

    def authorize_action(
        self,
        operation: str = "tool_call",
        *,
        capabilities: list[str] | None = None,
        consequence_tier: str | None = None,
        scope: str | None = None,
    ) -> dict:
        """Authorize an action. Returns the pre_commit receipt. Raises PermissionDenied on deny."""
        result = self._client.authorize(
            actor_svid=self.actor_svid,
            actor_capabilities=self.capabilities,
            operation_capabilities=capabilities or self.capabilities,
            consequence_tier=consequence_tier or self.default_tier,
            scope=scope or self.default_scope,
            operation_class=operation,
        )
        if result.verdict == "deny":
            raise PermissionDenied(result.gate or "unknown")
        receipt_id = result.receipt["predicate"]["binding"]["receipt_id"]
        self._pending[receipt_id] = result.receipt
        return result.receipt

    def attest_action(
        self,
        receipt: dict,
        *,
        outcome_status: str = "success",
        outcome_digest: str = "sha256:unknown",
    ) -> dict:
        """Attest the outcome of an action. Returns the post_commit receipt."""
        post = self._client.attest(
            receipt, outcome_status=outcome_status, outcome_digest=outcome_digest
        )
        return post

    def authorize_and_attest(
        self,
        operation: str = "tool_call",
        *,
        outcome_status: str = "success",
        outcome_digest: str = "sha256:unknown",
        capabilities: list[str] | None = None,
        consequence_tier: str | None = None,
        scope: str | None = None,
    ) -> tuple[dict, dict]:
        """Convenience: authorize, then immediately attest (for synchronous tool calls)."""
        pre = self.authorize_action(
            operation,
            capabilities=capabilities,
            consequence_tier=consequence_tier,
            scope=scope,
        )
        post = self.attest_action(pre, outcome_status=outcome_status, outcome_digest=outcome_digest)
        return pre, post
