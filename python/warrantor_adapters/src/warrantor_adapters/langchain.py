"""LangChain / LangGraph adapter.

Zero-dependency: if ``langchain_core`` is installed, :class:`WarrantorCallback` subclasses
``BaseCallbackHandler``. If not, the class still works against any caller that respects the
LangChain callback shape (``on_tool_start``, ``on_tool_end``).

Usage::

    from warrantor_adapters.langchain import WarrantorCallback
    agent.invoke(input, config={"callbacks": [WarrantorCallback(
        actor_svid="spiffe://yourcorp/agents/bot-1",
        capabilities=["read", "write"],
    )]})
"""

from __future__ import annotations

from typing import Any

from .base import WarrantorGuard

# Optional LangChain interop.
try:
    from langchain_core.callbacks import BaseCallbackHandler as _LCBase

    _HAS_LANGCHAIN = True
except Exception:
    _LCBase = object  # type: ignore[assignment, misc]
    _HAS_LANGCHAIN = False


def has_langchain() -> bool:
    return _HAS_LANGCHAIN


class WarrantorCallback(_LCBase):  # type: [misc]
    """LangChain BaseCallbackHandler that authorizes every tool call via Warrantor.

    On ``on_tool_start``: runs the 9-gate verdict; raises :class:`PermissionDenied` on deny.
    On ``on_tool_end``: attests the outcome.
    """

    def __init__(
        self,
        actor_svid: str,
        capabilities: list[str],
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self.guard = WarrantorGuard(actor_svid, capabilities, **kwargs)
        self._current_receipt: dict | None = None

    def on_tool_start(
        self, serialized: dict[str, Any] | None = None, input_str: str = "", **kwargs: Any
    ) -> None:
        """Authorize before the tool runs."""
        tool_name = (serialized or {}).get("name", kwargs.get("tool_name", "unknown_tool"))
        self._current_receipt = self.guard.authorize_action(operation=f"tool:{tool_name}")

    def on_tool_end(self, output: str = "", **kwargs: Any) -> None:
        """Attest the outcome after the tool completes."""
        if self._current_receipt is None:
            return
        outcome_digest = f"sha256:{abs(hash(output)) & 0xFFFFFFFFFFFFFFFF:016x}"
        self.guard.attest_action(
            self._current_receipt, outcome_status="success", outcome_digest=outcome_digest
        )
        self._current_receipt = None

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Attest a failure outcome."""
        if self._current_receipt is None:
            return
        self.guard.attest_action(
            self._current_receipt,
            outcome_status="error",
            outcome_digest=f"sha256:error:{type(error).__name__}",
        )
        self._current_receipt = None
