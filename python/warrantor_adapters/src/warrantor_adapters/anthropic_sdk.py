"""Anthropic SDK adapter.

The Anthropic Python SDK does not provide a formal lifecycle-hooks API like LangChain or the
OpenAI Agents SDK. Instead, this adapter provides:

- :class:`WarrantorToolGuard` — a context manager that wraps a single tool call.
- :func:`warrantor_guard` — a convenience factory.
- :func:`warrantor_tool` — a decorator that wraps any function as a Warrantor-governed tool.

Usage (context manager)::

    from warrantor_adapters.anthropic_sdk import warrantor_guard

    with warrantor_guard(actor_svid="spiffe://yourcorp/agents/bot-1", capabilities=["read"]) as g:
        result = my_tool(args)
        g.attest(outcome_digest="sha256:abc")

Usage (decorator)::

    from warrantor_adapters.anthropic_sdk import warrantor_tool

    @warrantor_tool(actor_svid="spiffe://yourcorp/agents/bot-1", capabilities=["read"])
    def get_weather(city: str) -> str:
        return f"Sunny in {city}"
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from .base import WarrantorGuard


class WarrantorToolGuard:
    """Context manager that authorizes on enter, attests on exit."""

    def __init__(self, guard: WarrantorGuard, operation: str = "tool_call") -> None:
        self._guard = guard
        self._operation = operation
        self._receipt: dict | None = None

    def __enter__(self) -> WarrantorToolGuard:
        self._receipt = self._guard.authorize_action(operation=self._operation)
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self._receipt is None:
            return
        if exc_type is not None:
            self._guard.attest_action(
                self._receipt,
                outcome_status="error",
                outcome_digest=f"sha256:error:{exc_type.__name__ if hasattr(exc_type, '__name__') else exc_type}",
            )
        else:
            self._guard.attest_action(
                self._receipt,
                outcome_status="success",
                outcome_digest="sha256:completed",
            )

    def attest(
        self, *, outcome_status: str = "success", outcome_digest: str = "sha256:unknown"
    ) -> None:
        """Manually attest a custom outcome (overrides the auto-attest on __exit__)."""
        if self._receipt is not None:
            self._guard.attest_action(
                self._receipt, outcome_status=outcome_status, outcome_digest=outcome_digest
            )
            self._receipt = None


def warrantor_guard(
    *,
    actor_svid: str,
    capabilities: list[str],
    operation: str = "tool_call",
    client: Any = None,
    **kwargs: Any,
) -> WarrantorToolGuard:
    """Factory: create a context-manager guard for a single tool call."""
    guard = WarrantorGuard(actor_svid, capabilities, client=client, **kwargs)
    return WarrantorToolGuard(guard, operation=operation)


def warrantor_tool(
    *,
    actor_svid: str,
    capabilities: list[str],
    operation: str | None = None,
    **kwargs: Any,
) -> Callable[[Callable], Callable]:
    """Decorator: wrap any function as a Warrantor-governed tool.

    The function runs inside a ``WarrantorToolGuard``; a deny verdict raises
    :class:`PermissionDenied` before the function body executes.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        op = operation or f"tool:{func.__name__}"

        @functools.wraps(func)
        def wrapper(*args: Any, **call_kwargs: Any) -> Any:
            guard = WarrantorGuard(actor_svid, capabilities, **kwargs)
            with WarrantorToolGuard(guard, operation=op):
                return func(*args, **call_kwargs)

        return wrapper

    return decorator
