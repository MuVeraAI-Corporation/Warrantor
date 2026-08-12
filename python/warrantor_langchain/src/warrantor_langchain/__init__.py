"""Warrantor LangChain/LangGraph harness adapter.

Wraps a LangChain agent so that:

  1. Every LLM and tool action is recorded as an **AAR** (Agent Action Record,
     P2 / E1 flight recorder).
  2. Every output is scanned for **secrets** (R4) and can **trigger the
     kill-switch** (R3) when a secret is exposed.
  3. Tool calls are gated by an **AAE** (Action Enforcer) permission check, so
     a tool can only run if the calling identity has the required permission.

The adapter is intentionally **zero-dependency**: if LangChain is installed,
``WarrantorCallback`` is also a real ``BaseCallbackHandler`` subclass. If
LangChain is **not** installed, the same class still works against any caller
that respects the LangChain callback handler shape (``on_llm_start``,
``on_tool_start``, ``on_tool_end``, etc.). This keeps the adapter useful in
constrained environments and makes it unit-testable without the heavy
``langchain`` dependency.

Usage:
    from warrantor_langchain import WarrantorCallback, WarrantorTool, wrap_agent

    callback = WarrantorCallback(identity="alice", permission_check=my_check)
    secured = wrap_agent(agent, identity="alice",
                         side_effect_class="write", callbacks=[callback])
"""

from __future__ import annotations

import contextlib
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Optional LangChain interop
# ---------------------------------------------------------------------------
try:  # pragma: no cover - environment dependent
    from langchain_core.callbacks import BaseCallbackHandler as _LCBase

    _HAS_LANGCHAIN = True
except Exception:
    _LCBase = object  # type: ignore[assignment, misc]
    _HAS_LANGCHAIN = False


# ---------------------------------------------------------------------------
# Secret scanning (subset of warrantor_harness patterns)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub PAT": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "Private Key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"),
}


def scan_for_secrets(text: str) -> list[str]:
    """Return the list of secret-type names detected in ``text``."""
    if not text:
        return []
    found: list[str] = []
    for name, pattern in _SECRET_PATTERNS.items():
        if pattern.search(text):
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# AAR (Agent Action Record) - the data structure written to the E1 log
# ---------------------------------------------------------------------------
@dataclass
class AAR:
    """Agent Action Record — one row in the E1 flight recorder."""

    aar_id: str
    identity: str
    action_type: str  # "llm", "tool", "chain", "agent"
    action_name: str
    side_effect_class: str = "read"
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    completed_at: float = 0.0
    secret_findings: list[str] = field(default_factory=list)
    kill_switch_triggered: bool = False
    error: str = ""

    @property
    def duration_ms(self) -> float:
        if not self.started_at or not self.completed_at:
            return 0.0
        return (self.completed_at - self.started_at) * 1000.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "aar_id": self.aar_id,
            "identity": self.identity,
            "action_type": self.action_type,
            "action_name": self.action_name,
            "side_effect_class": self.side_effect_class,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "secret_findings": self.secret_findings,
            "kill_switch_triggered": self.kill_switch_triggered,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Callback handler
# ---------------------------------------------------------------------------
PermissionCheck = Callable[[str, str], bool]
"""``(identity, permission_name) -> bool``. Used by ``WarrantorTool``."""


@dataclass
class WarrantorCallback(_LCBase):
    """LangChain-compatible callback handler that records AARs and scans secrets.

    The handler stores every AAR in ``self.aars`` so a caller (or a wrapping
    flight recorder) can flush them to disk. When ``kill_switch`` is set to a
    callable and a secret is detected in an LLM output, the kill-switch is
    invoked and the AAR is flagged ``kill_switch_triggered=True``.

    Attributes:
        identity:           subject id performing the actions.
        side_effect_class:  severity label copied onto every AAR
                            (read / write / financial / destructive / physical).
        permission_check:   optional callable used to gate tool calls.
        kill_switch:        optional callable invoked on secret exposure.
        kill_on_secret:     whether to actually invoke ``kill_switch``.
        sink:               optional callable invoked with each finished AAR.
    """

    identity: str = "anonymous"
    side_effect_class: str = "read"
    permission_check: PermissionCheck | None = None
    kill_switch: Callable[[AAR], None] | None = None
    kill_on_secret: bool = True
    sink: Callable[[AAR], None] | None = None
    aars: list[AAR] = field(default_factory=list)
    _open: dict[str, AAR] = field(default_factory=dict)

    # ``BaseCallbackHandler`` requires ``runs_nr`` etc. when present; we provide
    # the methods directly so both real-LangChain and standalone callers work.

    # ------------------------- LLM ----------------------------------------
    def on_llm_start(
        self,
        serialized: dict[str, Any] | None = None,
        prompts: list[str] | None = None,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        name = self._name_from_serialized(serialized) or "llm"
        aar = AAR(
            aar_id=run_id or str(uuid.uuid4()),
            identity=self.identity,
            action_type="llm",
            action_name=name,
            side_effect_class=self.side_effect_class,
            inputs={"prompts": prompts or [], "kwargs": kwargs},
            started_at=time.time(),
        )
        self._open[aar.aar_id] = aar
        return None

    def on_llm_end(self, output: Any, *, run_id: str | None = None, **kwargs: Any) -> Any:
        aar = self._pop_open(run_id, action_type="llm", fallback_name="llm")
        aar.outputs = self._coerce_output(output)
        self._finalize(aar)
        return None

    def on_llm_error(
        self, error: BaseException, *, run_id: str | None = None, **kwargs: Any
    ) -> Any:
        aar = self._pop_open(run_id, action_type="llm", fallback_name="llm")
        aar.error = repr(error)
        self._finalize(aar)
        return None

    # ------------------------- Tool ---------------------------------------
    def on_tool_start(
        self,
        serialized: dict[str, Any] | None = None,
        input_str: str = "",
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        name = self._name_from_serialized(serialized) or "tool"
        aar = AAR(
            aar_id=run_id or str(uuid.uuid4()),
            identity=self.identity,
            action_type="tool",
            action_name=name,
            side_effect_class=self.side_effect_class,
            inputs={"input": input_str, "kwargs": kwargs},
            started_at=time.time(),
        )
        self._open[aar.aar_id] = aar
        return None

    def on_tool_end(self, output: str, *, run_id: str | None = None, **kwargs: Any) -> Any:
        aar = self._pop_open(run_id, action_type="tool", fallback_name="tool")
        aar.outputs = {"output": str(output)}
        self._finalize(aar)
        return None

    def on_tool_error(
        self, error: BaseException, *, run_id: str | None = None, **kwargs: Any
    ) -> Any:
        aar = self._pop_open(run_id, action_type="tool", fallback_name="tool")
        aar.error = repr(error)
        self._finalize(aar)
        return None

    # ------------------------- Chain / Agent ------------------------------
    def on_chain_start(
        self,
        serialized: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        name = self._name_from_serialized(serialized) or "chain"
        aar = AAR(
            aar_id=run_id or str(uuid.uuid4()),
            identity=self.identity,
            action_type="chain",
            action_name=name,
            side_effect_class=self.side_effect_class,
            inputs=inputs or {},
            started_at=time.time(),
        )
        self._open[aar.aar_id] = aar
        return None

    def on_chain_end(
        self, outputs: dict[str, Any] | None = None, *, run_id: str | None = None, **kwargs: Any
    ) -> Any:
        aar = self._pop_open(run_id, action_type="chain", fallback_name="chain")
        aar.outputs = outputs or {}
        self._finalize(aar)
        return None

    # ------------------------- Helpers ------------------------------------
    @staticmethod
    def _name_from_serialized(serialized: dict[str, Any] | None) -> str:
        if not serialized:
            return ""
        # LangChain names live under kwargs.metadata.name or id (a list).
        name = serialized.get("name") or serialized.get("id")
        if isinstance(name, list):
            return str(name[-1]) if name else ""
        return str(name) if name else ""

    @staticmethod
    def _coerce_output(output: Any) -> dict[str, Any]:
        # LangChain LLMResult or ChatGeneration; we keep this defensive.
        if isinstance(output, dict):
            return output
        if hasattr(output, "model_dump"):
            try:
                return output.model_dump()  # type: ignore[no-any-return]
            except Exception:
                return {"repr": repr(output)}
        return {"repr": repr(output)}

    def _pop_open(self, run_id: str | None, *, action_type: str, fallback_name: str) -> AAR:
        if run_id and run_id in self._open:
            return self._open.pop(run_id)
        # No run_id correlation: pop the most recent open of this type.
        for aar_id in reversed(list(self._open.keys())):
            aar = self._open[aar_id]
            if aar.action_type == action_type:
                return self._open.pop(aar_id)
        return AAR(
            aar_id=run_id or str(uuid.uuid4()),
            identity=self.identity,
            action_type=action_type,
            action_name=fallback_name,
            side_effect_class=self.side_effect_class,
            started_at=time.time(),
        )

    def _finalize(self, aar: AAR) -> None:
        aar.completed_at = time.time()
        # Scan all string outputs for secrets.
        blob = self._stringify_for_scan(aar.outputs)
        aar.secret_findings = scan_for_secrets(blob)
        if aar.secret_findings and self.kill_on_secret and self.kill_switch is not None:
            aar.kill_switch_triggered = True
            try:
                self.kill_switch(aar)
            except Exception as exc:
                aar.error = aar.error or f"kill_switch raised: {exc!r}"
        self.aars.append(aar)
        if self.sink is not None:
            with contextlib.suppress(Exception):
                self.sink(aar)

    @staticmethod
    def _stringify_for_scan(outputs: dict[str, Any]) -> str:
        parts: list[str] = []
        for v in outputs.values():
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, list):
                parts.extend(str(x) for x in v)
            else:
                parts.append(str(v))
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# WarrantorTool — wraps a callable so it can only run with AAE permission
# ---------------------------------------------------------------------------
class PermissionDenied(Exception):
    """Raised by ``WarrantorTool`` when the AAE permission check fails."""

    def __init__(self, identity: str, permission: str) -> None:
        self.identity = identity
        self.permission = permission
        super().__init__(f"Permission denied: {identity!r} lacks permission {permission!r}")


@dataclass
class WarrantorTool:
    """Callable wrapper that gates execution behind an AAE permission check.

    The wrapper duck-types as a LangChain ``Tool``-ish object (``name``,
    ``description``, ``func``). When called, it consults the supplied
    ``permission_check(identity, permission)`` and raises ``PermissionDenied``
    on failure. Otherwise it invokes the wrapped callable and returns its
    result.
    """

    name: str
    description: str
    func: Callable[..., Any]
    permission: str
    identity: str = "anonymous"
    permission_check: PermissionCheck | None = None
    # Optional callback that records an AAR for the tool call.
    on_call: Callable[[str, dict[str, Any], Any], None] | None = None

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self.permission_check is None:
            check_ok = True
        else:
            check_ok = bool(self.permission_check(self.identity, self.permission))
        if not check_ok:
            raise PermissionDenied(self.identity, self.permission)
        result = self.func(*args, **kwargs)
        if self.on_call is not None:
            with contextlib.suppress(Exception):
                self.on_call(self.name, {"args": args, "kwargs": kwargs}, result)
        return result

    # LangChain tool protocol-ish accessors
    def _run(self, *args: Any, **kwargs: Any) -> Any:
        return self(*args, **kwargs)


# ---------------------------------------------------------------------------
# wrap_agent — wrap a LangChain-style agent with Warrantor security
# ---------------------------------------------------------------------------
@dataclass
class SecuredAgent:
    """Container returned by ``wrap_agent``.

    Holds the wrapped agent, the active callback, and the side-effect class.
    Callers can invoke ``run`` if the underlying agent supports it; otherwise
    they interact with ``agent`` directly and the callback records activity.
    """

    agent: Any
    callback: WarrantorCallback
    identity: str
    side_effect_class: str

    def run(self, *args: Any, **kwargs: Any) -> Any:
        if not hasattr(self.agent, "run"):
            raise AttributeError("wrapped agent has no .run() method")
        return self.agent.run(*args, **kwargs)


def wrap_agent(
    agent: Any,
    *,
    identity: str,
    side_effect_class: str = "write",
    permission_check: PermissionCheck | None = None,
    kill_switch: Callable[[AAR], None] | None = None,
    kill_on_secret: bool = True,
    sink: Callable[[AAR], None] | None = None,
    extra_callbacks: list[Any] | None = None,
) -> SecuredAgent:
    """Wrap a LangChain agent with an ``WarrantorCallback`` and return a container.

    The callback is attached to the agent by setting
    ``agent.callbacks`` (creating the list if needed). When ``langchain`` is
    absent this still works for any duck-typed object exposing a ``callbacks``
    attribute or accepting callbacks via ``agent.run(..., callbacks=[...])``.
    """
    callback = WarrantorCallback(
        identity=identity,
        side_effect_class=side_effect_class,
        permission_check=permission_check,
        kill_switch=kill_switch,
        kill_on_secret=kill_on_secret,
        sink=sink,
    )
    callbacks_list: list[Any] = [callback]
    if extra_callbacks:
        callbacks_list.extend(extra_callbacks)
    # Try to attach. Be defensive: the agent may be immutable / frozen.
    try:
        existing = list(getattr(agent, "callbacks", []) or [])
        agent.callbacks = [*existing, *callbacks_list]  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        pass
    return SecuredAgent(
        agent=agent,
        callback=callback,
        identity=identity,
        side_effect_class=side_effect_class,
    )


def has_langchain() -> bool:
    """Return ``True`` if a real ``langchain_core`` is importable."""
    return _HAS_LANGCHAIN


__all__ = [
    "AAR",
    "PermissionCheck",
    "PermissionDenied",
    "SecuredAgent",
    "WarrantorCallback",
    "WarrantorTool",
    "has_langchain",
    "scan_for_secrets",
    "wrap_agent",
]
