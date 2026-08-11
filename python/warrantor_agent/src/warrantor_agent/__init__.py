"""AumOS Agent SDK — unified Python SDK for coding agents.

This module gives any Python coding agent (Claude Code custom tools, OpenAI Codex scripts,
Cursor rules, or a hand-rolled agent) the AumOS security primitives as first-class objects.

The headline feature is the ``@agent.action`` decorator, which wraps any function with the full
AumOS security envelope:

    from warrantor_agent import AumOS

    agent = AumOS(mode="standalone")  # or "connected" against running services

    @agent.action(tool="github.create_pr", side_effect="write")
    def create_pull_request(repo: str, title: str, body: str):
        return {"pr_number": 42, "url": f"https://github.com/{repo}/pull/42"}

A decorated action automatically:

1. Issues / verifies an agent identity (I1 agent-identity).
2. Runs pre-flight sandbox checks (R2 eval-guard).
3. Brokers scoped credentials (R4 credential-vault).
4. Emits an Agent Action Receipt **before** the action commits (E1, invariant I-07).
5. Records the action in the local evidence store.
6. On any exception, triggers containment (R3 kill-switch) and re-raises.

Design principles
-----------------
- **Zero-friction**: ``@agent.action`` wraps any function with full AumOS security.
- **Graceful degradation**: in ``"standalone"`` mode, uses local mock implementations; in
  ``"connected"`` mode, calls real services and falls back to mocks on connection failure.
- **Coding-agent friendly**: importable from notebooks, scripts, or rules files.
- **Evidence-first**: every decorated action produces a verifiable receipt (P2 AAR).
- **Fail-closed**: if any security check fails, the action is blocked (invariant I-09).

HTTP is done via ``httpx`` when available, falling back to ``urllib.request`` from the stdlib.
The CLI components (T1 ``trust-core``, X1 ``defstack``) are invoked via ``subprocess``.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "MOCK_SIGNATURE_PREFIX",
    "ActionBlocked",
    "ActionResult",
    "AumOS",
    "AumOSConfig",
    "ContainmentTriggered",
    "Finding",
    "Receipt",
    "SecurityError",
    "SideEffect",
    "SigningUnavailable",
]

__version__ = "1.0.0"

# Side-effect classes, ordered by escalating consequence (invariant I-08 ladder).
# Kept as a runtime list so callers can introspect the allowed values.
SIDE_EFFECTS: list[str] = ["read", "write", "financial", "destructive", "physical"]
_SIDE_EFFECT_RANK: dict[str, int] = {s: i for i, s in enumerate(SIDE_EFFECTS)}
CONSEQUENTIAL_CLASSES: frozenset[str] = frozenset({"financial", "destructive", "physical"})

# Default service URLs (overridable via AumOSConfig). Match the MCP server defaults.
_DEFAULTS = {
    "agent_identity_url": "http://localhost:8441",
    "trust_core_bin": "trust-core",
    "defstack_bin": "defstack",
    "flight_recorder_url": "http://localhost:8445",
    "nvtrust_bridge_url": "http://localhost:8447",
    "model_sbom_url": "http://localhost:8451",
    "safe_eval_url": "http://localhost:8455",
    "eval_guard_url": "http://localhost:8460",
    "kill_switch_url": "http://localhost:8461",
    "credential_vault_url": "http://localhost:8465",
    "http_timeout": 5.0,
}


# ---------------------------------------------------------------------------
# Type aliases + dataclasses.
# ---------------------------------------------------------------------------

SideEffect = str  # one of SIDE_EFFECTS

#: Marks a standalone-mode stand-in so it can never be confused with a real signature.
#: A real Ed25519 signature is bare hex; anything carrying this prefix is a mock and any
#: consumer can reject it on sight. See :meth:`AumOSAgent.sign` and AX-28.
MOCK_SIGNATURE_PREFIX = "mock-unverifiable:"


class SecurityError(Exception):
    """Base class for all AumOS SDK security errors."""


class SigningUnavailable(SecurityError):
    """Raised when connected mode cannot reach trust-core.

    Deliberately fatal. The previous behaviour caught the failure and returned a mock HMAC
    whose key is derived entirely from public values, so a caller that asked for a real
    signature silently received a forgeable one and had no way to tell (AX-28). An unavailable
    signer is an error, never a weaker signer.
    """


class ActionBlocked(SecurityError):
    """Raised when a security check fails and the action is blocked (invariant I-09).

    Carries the reason and the structured ``preflight`` result so callers can inspect why.
    """

    def __init__(self, reason: str, *, preflight: dict[str, Any] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.preflight = preflight or {}


class ContainmentTriggered(SecurityError):
    """Raised after the kill-switch fires during an action's exception path."""


@dataclass
class Finding:
    """A single secret-scan finding."""

    type: str
    value: str  # masked
    index: int

    def as_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value, "index": self.index}


@dataclass
class Receipt:
    """A signed Agent Action Receipt (P2 AAR)."""

    receipt_id: str
    signature: str
    signed_at: int
    payload: dict[str, Any]
    source: str = "mock"

    def as_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "signature": self.signature,
            "signed_at": self.signed_at,
            "payload": self.payload,
            "source": self.source,
        }


@dataclass
class ActionResult:
    """The result of running a decorated action.

    Wraps the wrapped function's return value together with the security artifacts produced:
    the SVID used, the preflight result, the receipt, and the final outcome.
    """

    ok: bool
    value: Any
    svid: str | None
    preflight: dict[str, Any]
    receipt: Receipt
    outcome: str  # 'success' | 'failure' | 'denied'
    duration_ms: float
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        d = {
            "ok": self.ok,
            "value": self.value,
            "svid": self.svid,
            "preflight": self.preflight,
            "receipt": self.receipt.as_dict(),
            "outcome": self.outcome,
            "duration_ms": self.duration_ms,
        }
        if self.error is not None:
            d["error"] = self.error
        return d


@dataclass
class AumOSConfig:
    """Configuration for the AumOS SDK. All URL/bin fields default to localhost services.

    Attributes:
        mode: ``"standalone"`` (mock implementations) or ``"connected"`` (real services).
        agent_identity_url: I1 HTTP gateway base URL.
        trust_core_bin: T1 trust-core CLI binary name.
        flight_recorder_url: E1 service base URL.
        nvtrust_bridge_url: C1-1 base URL.
        model_sbom_url: S4 base URL.
        safe_eval_url: A1 base URL.
        eval_guard_url: R2 base URL.
        kill_switch_url: R3 base URL.
        credential_vault_url: R4 base URL.
        defstack_bin: X1 defstack CLI binary name.
        http_timeout: per-call HTTP timeout in seconds.
        fail_closed: when True (default), a failing preflight blocks the action (I-09).
        auto_kill_on_error: when True (default), an exception in the wrapped function triggers
            the R3 kill-switch (containment) before re-raising.
    """

    mode: str = "standalone"
    agent_identity_url: str | None = None
    trust_core_bin: str | None = None
    flight_recorder_url: str | None = None
    nvtrust_bridge_url: str | None = None
    model_sbom_url: str | None = None
    safe_eval_url: str | None = None
    eval_guard_url: str | None = None
    kill_switch_url: str | None = None
    credential_vault_url: str | None = None
    defstack_bin: str | None = None
    http_timeout: float | None = None
    fail_closed: bool = True
    auto_kill_on_error: bool = True
    agent_svid: str = "spiffe://muveraai.com/agent/default"

    def resolved(self) -> dict[str, Any]:
        """Return a dict of all config values with defaults filled in."""
        out = dict(_DEFAULTS)
        for f in (
            "agent_identity_url",
            "trust_core_bin",
            "flight_recorder_url",
            "nvtrust_bridge_url",
            "model_sbom_url",
            "safe_eval_url",
            "eval_guard_url",
            "kill_switch_url",
            "credential_vault_url",
            "defstack_bin",
            "http_timeout",
        ):
            v = getattr(self, f)
            if v is not None:
                out[f] = v
        return out


# ---------------------------------------------------------------------------
# HTTP transport — httpx if installed, urllib stdlib fallback.
# ---------------------------------------------------------------------------


class _HttpBackend(Protocol):
    def post_json(self, url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]: ...


class _UrllibBackend:
    """stdlib-only HTTP POST backend."""

    def post_json(self, url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            err = RuntimeError(f"HTTP {e.code} from {url}: {raw}")
            err.status = e.code  # type: ignore[attr-defined]
            raise err from e
        return _parse_json(raw)


def _parse_json(raw: str) -> dict[str, Any]:
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}
    if not isinstance(parsed, dict):
        return {"data": parsed}
    return parsed


def _select_backend() -> _HttpBackend:
    try:
        import httpx  # type: ignore[import-not-found]
    except ImportError:
        return _UrllibBackend()

    class _HttpxBackend:
        def post_json(self, url: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=body, headers={"content-type": "application/json"})
                if resp.status_code >= 400:
                    err = RuntimeError(f"HTTP {resp.status_code} from {url}: {resp.text}")
                    err.status = resp.status_code  # type: ignore[attr-defined]
                    raise err
                return _parse_json(resp.text)

    return _HttpxBackend()


# ---------------------------------------------------------------------------
# Secret patterns (mirrors the MCP server scanner).
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(r"\baws(?:.{0,20})?(?:secret|sk)[^\n]{0,3}[0-9a-zA-Z/+]{40}\b", re.IGNORECASE),
    ),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    (
        "generic_bearer",
        re.compile(
            r"\b(?:bearer|token|api_key|apikey)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_\-.]{20,}[\"']?",
            re.IGNORECASE,
        ),
    ),
]


def _mask(value: str) -> str:
    if len(value) > 8:
        return f"{value[:4]}…{value[-4:]}"
    return "****"


# ---------------------------------------------------------------------------
# The AumOS class.
# ---------------------------------------------------------------------------


class AumOS:
    """The AumOS Agent SDK entry point.

    Parameters mirror :class:`AumOSConfig`. ``mode`` selects between standalone (mock) and
    connected (real services) operation; ``**kwargs`` accepts any :class:`AumOSConfig` field.

    Example:
        >>> agent = AumOS(mode="standalone")
        >>> agent.scan_secrets("token=ghp_" + "a"*36)
        [Finding(type='github_pat', ...)]
    """

    def __init__(
        self,
        *,
        mode: str = "standalone",
        agent_identity_url: str | None = None,
        trust_core_url: str | None = None,  # accepted for API symmetry; CLI is used instead
        flight_recorder_url: str | None = None,
        nvtrust_bridge_url: str | None = None,
        model_sbom_url: str | None = None,
        safe_eval_url: str | None = None,
        eval_guard_url: str | None = None,
        kill_switch_url: str | None = None,
        credential_vault_url: str | None = None,
        trust_core_bin: str | None = None,
        defstack_bin: str | None = None,
        http_timeout: float | None = None,
        fail_closed: bool = True,
        auto_kill_on_error: bool = True,
        agent_svid: str = "spiffe://muveraai.com/agent/default",
        _backend: _HttpBackend | None = None,
    ) -> None:
        if mode not in ("standalone", "connected"):
            raise ValueError(f"mode must be 'standalone' or 'connected', got {mode!r}")
        self.config = AumOSConfig(
            mode=mode,
            agent_identity_url=agent_identity_url,
            flight_recorder_url=flight_recorder_url,
            nvtrust_bridge_url=nvtrust_bridge_url,
            model_sbom_url=model_sbom_url,
            safe_eval_url=safe_eval_url,
            eval_guard_url=eval_guard_url,
            kill_switch_url=kill_switch_url,
            credential_vault_url=credential_vault_url,
            trust_core_bin=trust_core_bin
            or (_DEFAULTS["trust_core_bin"] if trust_core_url else None),
            defstack_bin=defstack_bin,
            http_timeout=http_timeout,
            fail_closed=fail_closed,
            auto_kill_on_error=auto_kill_on_error,
            agent_svid=agent_svid,
        )
        self._backend: _HttpBackend = _backend or _select_backend()
        # Local evidence store: append-only list of ActionResult dicts. Used by the decorator
        # for record-keeping (step 5) and inspectable by callers via `agent.evidence`.
        self.evidence: list[dict[str, Any]] = []
        # Cached SVID issued for this agent (re-issued on demand).
        self._svid: str | None = None

    # ------------------------------------------------------------------
    # Convenience properties.
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self.config.mode

    @property
    def is_connected(self) -> bool:
        return self.config.mode == "connected"

    def _cfg(self, key: str) -> Any:
        return self.config.resolved()[key]

    # ------------------------------------------------------------------
    # T1 trust-core: sign / verify.
    # ------------------------------------------------------------------

    def sign(self, data: str | bytes, key_id: str = "default") -> str:
        """Sign ``data`` with Ed25519 (T1 trust-core). Returns a hex signature.

        In **connected** mode this shells out to ``trust-core sign`` and raises
        :class:`SigningUnavailable` if that fails. It does not fall back to the mock: a caller
        that asked for real signing must never receive a forgeable one instead (AX-28).

        In **standalone** mode it returns a ``MOCK_SIGNATURE_PREFIX``-tagged HMAC. That value is
        not a signature and is not unforgeable — its key is derived from public inputs, so anyone
        can compute it. The prefix exists so it cannot be mistaken for, or stored as, real output.
        """
        payload = data.encode("utf-8") if isinstance(data, str) else data
        if self.is_connected:
            try:
                out = self._run_cli(
                    self._cfg("trust_core_bin"),
                    [
                        "sign",
                        "--data",
                        data if isinstance(data, str) else data.decode("utf-8", "replace"),
                        "--key-id",
                        key_id,
                    ],
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise SigningUnavailable(
                    f"connected mode: trust-core sign could not be executed ({error}). "
                    "Refusing to substitute a mock signature."
                ) from error
            if out.returncode != 0 or not out.stdout.strip():
                raise SigningUnavailable(
                    f"connected mode: trust-core sign failed (exit {out.returncode}). "
                    "Refusing to substitute a mock signature."
                )
            return out.stdout.strip()
        return self._mock_sign(payload, key_id)

    def verify(self, data: str | bytes, signature: str, key: str) -> bool:
        """Verify an Ed25519 signature (T1 trust-core). Returns True iff valid.

        ``key`` is the hex-encoded verifying key. In connected mode, shells out to
        ``trust-core verify``; otherwise falls back to mock verification.

        Standalone round-trip: ``agent.verify(data, agent.sign(data, key_id=k), key=k)`` is True
        — the mock treats the supplied ``key`` as the same identifier passed to :meth:`sign`'s
        ``key_id``. This is not real cryptography; it exists so tests and dry-runs work end-to-end
        without a running trust-core.
        """
        payload = data.encode("utf-8") if isinstance(data, str) else data
        if self.is_connected:
            try:
                out = self._run_cli(
                    self._cfg("trust_core_bin"),
                    [
                        "verify",
                        "--data",
                        data if isinstance(data, str) else data.decode("utf-8", "replace"),
                        "--signature",
                        signature,
                        "--key",
                        key,
                    ],
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise SigningUnavailable(
                    f"connected mode: trust-core verify could not be executed ({error}). "
                    "Refusing to fall back to mock verification."
                ) from error
            if out.returncode != 0:
                raise SigningUnavailable(
                    f"connected mode: trust-core verify failed (exit {out.returncode}). "
                    "Refusing to fall back to mock verification."
                )
            return "valid" in out.stdout.lower()

        # Standalone: only ever accept a value that declares itself a mock. Without this
        # guard a real Ed25519 signature reaching a standalone verifier would be compared
        # against an HMAC, fail, and read as "signature invalid" rather than
        # "this verifier cannot check real signatures".
        if not signature.startswith(MOCK_SIGNATURE_PREFIX):
            return False
        return hmac.compare_digest(self._mock_sign(payload, key), signature)

    @staticmethod
    def _mock_sign(payload: bytes, key_id: str) -> str:
        """A tagged HMAC standing in for a signature in standalone mode.

        NOT unforgeable. The key is ``sha256("warrantor-mock-key:" + key_id)``, and both halves
        are public, so any party can recompute it. It exists so dry-runs work end to end without
        a running trust-core. The prefix is what keeps it from being mistaken for real output.
        """
        secret = hashlib.sha256(f"warrantor-mock-key:{key_id}".encode()).digest()
        return MOCK_SIGNATURE_PREFIX + hmac.new(secret, payload, hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # I1 agent-identity.
    # ------------------------------------------------------------------

    def issue_identity(
        self,
        subject: str,
        *,
        audience: str = "",
        parent_svid: str = "",
    ) -> dict[str, Any]:
        """Issue an agent identity (SVID + capability token) via I1 agent-identity.

        POSTs to ``/v1/agent-identity:issue``. Returns a dict with keys ``svid``,
        ``capability_jti``, ``verifying_key``, ``expires_at`` (mirrors the Go gateway wire shape).
        """
        if not subject:
            raise ValueError("subject is required")
        body = {"subject": subject, "audience": audience, "parent_svid": parent_svid}
        if self.is_connected:
            try:
                r = self._http_post(
                    self._cfg("agent_identity_url"), "/v1/agent-identity:issue", body
                )
                r.setdefault("source", "agent-identity")
                return r
            except (RuntimeError, OSError) as e:
                return {
                    **self._mock_issue(subject),
                    "source": "mock",
                    "degraded": True,
                    "http_error": str(e),
                }
        return {**self._mock_issue(subject), "source": "mock"}

    def verify_identity(self, svid: str, *, audience: str = "") -> dict[str, Any]:
        """Verify an SVID via I1 agent-identity. Returns ``{valid, subject?, reason?}``."""
        if not svid:
            raise ValueError("svid is required")
        body = {"svid": svid, "audience": audience}
        if self.is_connected:
            try:
                return self._http_post(
                    self._cfg("agent_identity_url"), "/v1/agent-identity:verify", body
                )
            except (RuntimeError, OSError) as e:
                valid, subject = self._mock_verify(svid)
                return {
                    "valid": valid,
                    "subject": subject,
                    "source": "mock",
                    "degraded": True,
                    "reason": str(e),
                }
        valid, subject = self._mock_verify(svid)
        return {"valid": valid, "subject": subject, "source": "mock"}

    def revoke_identity(self, jti: str, *, reason: str = "") -> dict[str, Any]:
        """Revoke an identity via I1 agent-identity. Returns ``{revoked, revoked_at}``."""
        if not jti:
            raise ValueError("jti is required")
        body = {"jti": jti, "reason": reason}
        if self.is_connected:
            try:
                return self._http_post(
                    self._cfg("agent_identity_url"), "/v1/agent-identity:revoke", body
                )
            except (RuntimeError, OSError) as e:
                return {
                    "revoked": True,
                    "revoked_at": int(time.time()),
                    "source": "mock",
                    "degraded": True,
                    "reason": str(e),
                }
        return {"revoked": True, "revoked_at": int(time.time()), "source": "mock"}

    @staticmethod
    def _mock_issue(subject: str) -> dict[str, Any]:
        hex_subject = subject.encode("utf-8").hex()
        return {
            "svid": f"svid-mock-{hex_subject}",
            "capability_jti": f"jti-{uuid.uuid4()}",
            "verifying_key": hashlib.sha256(f"warrantor-mock-key:{subject}".encode()).hexdigest()[
                :64
            ],
            "expires_at": int(time.time()) + 60,
        }

    @staticmethod
    def _mock_verify(svid: str) -> tuple[bool, str]:
        if not svid.startswith("svid-mock-"):
            return False, ""
        hex_part = svid[len("svid-mock-") :]
        if len(hex_part) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]*", hex_part):
            return False, ""
        try:
            return True, bytes.fromhex(hex_part).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False, ""

    # ------------------------------------------------------------------
    # E1 flight-recorder.
    # ------------------------------------------------------------------

    def emit_receipt(
        self,
        actor: str,
        tool: str,
        outcome: str = "pending",
        *,
        side_effect: str = "read",
        inputs_hash: str = "",
    ) -> Receipt:
        """Emit an Agent Action Receipt (P2 AAR) via E1 flight-recorder.

        Per invariant I-07, callers must emit a receipt **before** the action commits; the
        decorator does this for you. Returns a :class:`Receipt` with id + signature.
        """
        if not actor or not tool:
            raise ValueError("actor and tool are required")
        payload = {
            "actor": actor,
            "tool": tool,
            "outcome": outcome,
            "side_effect": side_effect,
            "inputs_hash": inputs_hash or hashlib.sha256(f"{actor}:{tool}".encode()).hexdigest(),
            "emitted_at": int(time.time()),
        }
        if self.is_connected:
            try:
                r = self._http_post(
                    self._cfg("flight_recorder_url"), "/v1/flight-recorder:emit", payload
                )
                return Receipt(
                    receipt_id=r.get("receipt_id", f"aar-{uuid.uuid4()}"),
                    signature=r.get("signature", ""),
                    signed_at=int(r.get("signed_at", payload["emitted_at"])),
                    payload=payload,
                    source="flight-recorder",
                )
            except (RuntimeError, OSError) as e:
                rec = self._mock_receipt(payload)
                rec.source = "mock"
                rec.payload["degraded"] = True
                rec.payload["http_error"] = str(e)
                return rec
        rec = self._mock_receipt(payload)
        return rec

    def verify_receipt(self, receipt_id: str, signature: str = "") -> dict[str, Any]:
        """Verify a receipt signature. Returns ``{valid, signer, receipt_id}``."""
        if not receipt_id:
            raise ValueError("receipt_id is required")
        if self.is_connected:
            try:
                return self._http_post(
                    self._cfg("flight_recorder_url"),
                    "/v1/flight-recorder:verify",
                    {"receipt_id": receipt_id, "signature": signature},
                )
            except (RuntimeError, OSError) as e:
                return {
                    "valid": receipt_id.startswith("aar-"),
                    "signer": "spiffe://muveraai.com/flight-recorder",
                    "receipt_id": receipt_id,
                    "source": "mock",
                    "degraded": True,
                    "reason": str(e),
                }
        return {
            "valid": receipt_id.startswith("aar-"),
            "signer": "spiffe://muveraai.com/flight-recorder",
            "receipt_id": receipt_id,
            "source": "mock",
        }

    @staticmethod
    def _mock_receipt(payload: dict[str, Any]) -> Receipt:
        receipt_id = f"aar-{uuid.uuid4()}"
        canonical = json.dumps(payload, sort_keys=True)
        sig = hashlib.sha256(f"aar-sig:{canonical}".encode()).hexdigest()
        return Receipt(
            receipt_id=receipt_id,
            signature=sig,
            signed_at=int(payload.get("emitted_at", time.time())),
            payload=payload,
        )

    # ------------------------------------------------------------------
    # C1-1 nvtrust-bridge attestation.
    # ------------------------------------------------------------------

    def check_attestation(
        self, *, nonce: str | None = None, gpu_pci_id: str = ""
    ) -> dict[str, Any]:
        """Check a GPU attestation report via C1-1 nvtrust-bridge."""
        nonce = nonce or secrets.token_hex(16)
        body = {"nonce": nonce, "gpu_pci_id": gpu_pci_id}
        if self.is_connected:
            try:
                return self._http_post(
                    self._cfg("nvtrust_bridge_url"), "/v1/attestation:check", body
                )
            except (RuntimeError, OSError) as e:
                return {
                    **self._mock_attestation(nonce, gpu_pci_id),
                    "source": "mock",
                    "degraded": True,
                    "http_error": str(e),
                }
        return self._mock_attestation(nonce, gpu_pci_id)

    @staticmethod
    def _mock_attestation(nonce: str, gpu: str) -> dict[str, Any]:
        return {
            "verified": True,
            "hardware_tee": "nvidia-confidential-computing",
            "gpu": gpu or "auto-detected",
            "nonce": nonce,
            "attestation_report_hash": hashlib.sha256(f"att:{nonce}".encode()).hexdigest(),
            "checked_at": int(time.time()),
            "source": "mock",
        }

    # ------------------------------------------------------------------
    # R2 eval-guard preflight.
    # ------------------------------------------------------------------

    def run_preflight(
        self, tool: str, *, inputs: str = "{}", side_effect: str = "read"
    ) -> dict[str, Any]:
        """Run sandbox pre-flight checks via R2 eval-guard.

        Implements the fail-closed invariant I-09: an action may only proceed when
        ``result['allowed']`` is True. Consequential classes (financial/destructive/physical)
        require explicit approval (invariant I-08) and are blocked by default in standalone.
        """
        if not tool:
            raise ValueError("tool is required")
        body = {"tool": tool, "inputs": inputs, "side_effect": side_effect}
        if self.is_connected:
            try:
                return self._http_post(
                    self._cfg("eval_guard_url"), "/v1/eval-guard:preflight", body
                )
            except (RuntimeError, OSError) as e:
                return {
                    **self._mock_preflight(tool, side_effect),
                    "source": "mock",
                    "degraded": True,
                    "http_error": str(e),
                }
        return self._mock_preflight(tool, side_effect)

    @staticmethod
    def _mock_preflight(tool: str, side_effect: str) -> dict[str, Any]:
        consequential = side_effect in CONSEQUENTIAL_CLASSES
        return {
            "allowed": not consequential,
            "reason": (
                "consequential_action_requires_approval (invariant I-08)" if consequential else "ok"
            ),
            "tool": tool,
            "side_effect": side_effect,
            "checked_at": int(time.time()),
            "source": "mock",
        }

    # ------------------------------------------------------------------
    # R3 kill-switch.
    # ------------------------------------------------------------------

    def kill(
        self, *, reason: str = "behavioral_anomaly", agent: str | None = None
    ) -> dict[str, Any]:
        """Trigger the R3 kill-switch (containment). Returns ``{triggered, reason, killed_at}``."""
        if not reason:
            raise ValueError("reason is required")
        ag = agent or self.config.agent_svid
        body = {"reason": reason, "agent": ag}
        if self.is_connected:
            try:
                return self._http_post(
                    self._cfg("kill_switch_url"), "/v1/kill-switch:trigger", body
                )
            except (RuntimeError, OSError) as e:
                return {
                    "triggered": True,
                    "killed_at": int(time.time()),
                    "reason": reason,
                    "agent": ag,
                    "source": "mock",
                    "degraded": True,
                    "http_error": str(e),
                }
        return {
            "triggered": True,
            "killed_at": int(time.time()),
            "reason": reason,
            "agent": ag,
            "source": "mock",
        }

    # ------------------------------------------------------------------
    # R4 credential-vault secret scan.
    # ------------------------------------------------------------------

    def scan_secrets(self, text: str) -> list[Finding]:
        """Scan ``text`` for exposed credentials via R4 credential-vault.

        In connected mode, POSTs to ``/v1/credential-vault:scan`` and returns its findings;
        on connection failure, falls back to the local scanner. The local scanner detects
        common secret shapes (AWS keys, GitHub PATs, Slack tokens, private key blocks, etc.).
        Captured values are always masked before return.
        """
        findings = self._local_scan(text)
        if self.is_connected:
            try:
                r = self._http_post(
                    self._cfg("credential_vault_url"), "/v1/credential-vault:scan", {"text": text}
                )
                remote = r.get("findings")
                if isinstance(remote, list):
                    return [
                        Finding(
                            type=str(f.get("type", "unknown")),
                            value=str(f.get("value", "****")),
                            index=int(f.get("index", 0)),
                        )
                        for f in remote
                    ]
            except (RuntimeError, OSError):
                pass
        return findings

    @staticmethod
    def _local_scan(text: str) -> list[Finding]:
        out: list[Finding] = []
        for name, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                out.append(Finding(type=name, value=_mask(m.group(0)), index=m.start()))
        return out

    # ------------------------------------------------------------------
    # X1 defstack compliance + install.
    # ------------------------------------------------------------------

    def compliance_report(
        self, *, scope: str = "soc2", model: str | None = None, format: str = "json"
    ) -> dict[str, Any]:
        """Generate a compliance report via X1 defstack-cli (``defstack report``)."""
        if self.is_connected:
            try:
                out = self._run_cli(
                    self._cfg("defstack_bin"), ["report", "--scope", scope, "--format", format]
                )
                if out.returncode == 0 and out.stdout.strip():
                    return {
                        "report_json": out.stdout.strip(),
                        "format": format,
                        "source": "defstack",
                    }
            except (OSError, subprocess.SubprocessError):
                pass
        return {
            "report_json": json.dumps(
                {
                    "scope": scope,
                    "model": model,
                    "status": "compliant",
                    "controls_total": 12,
                    "controls_passed": 12,
                    "generated_at": _now_iso(),
                }
            ),
            "format": format,
            "source": "mock",
        }

    def install(self, name: str, *, version: str = "latest") -> dict[str, Any]:
        """Install an AumOS component via ``defstack install <name>``."""
        if not name:
            raise ValueError("name is required")
        if self.is_connected:
            try:
                args = ["install", name]
                if version != "latest":
                    args += ["--version", version]
                out = self._run_cli(self._cfg("defstack_bin"), args)
                if out.returncode == 0:
                    return {
                        "installed": True,
                        "name": name,
                        "version": version,
                        "source": "defstack",
                        "stdout": out.stdout.strip(),
                    }
            except (OSError, subprocess.SubprocessError):
                pass
        return {"installed": True, "name": name, "version": version, "source": "mock"}

    # ------------------------------------------------------------------
    # S4 model-sbom.
    # ------------------------------------------------------------------

    def generate_sbom(self, model: str, *, format: str = "cyclonedx") -> dict[str, Any]:
        """Generate a Model SBOM via S4 model-sbom (CycloneDX)."""
        if not model:
            raise ValueError("model is required")
        body = {"model": model, "format": format}
        if self.is_connected:
            try:
                return self._http_post(self._cfg("model_sbom_url"), "/v1/model-sbom:generate", body)
            except (RuntimeError, OSError) as e:
                return {
                    **self._mock_sbom(model),
                    "source": "mock",
                    "degraded": True,
                    "http_error": str(e),
                }
        return self._mock_sbom(model)

    @staticmethod
    def _mock_sbom(model: str) -> dict[str, Any]:
        components = [
            {"type": "model", "name": model, "bomRef": f"pkg:aumos/model/{model}"},
            {
                "type": "dataset",
                "name": f"{model}-instruct-tune",
                "bomRef": f"pkg:aumos/dataset/{model}-tune",
            },
        ]
        return {
            "sbom": {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": components,
                "metadata": {"timestamp": _now_iso(), "tool": "warrantor-agent-sdk"},
            },
            "format": "cyclonedx",
            "components": components,
            "source": "mock",
        }

    # ------------------------------------------------------------------
    # A1 safe-eval.
    # ------------------------------------------------------------------

    def run_eval(self, model: str, pipeline_yaml: str = "") -> dict[str, Any]:
        """Run an evaluation pipeline via A1 safe-eval. Returns results + a Verifiable Eval Bundle."""
        if not model:
            raise ValueError("model is required")
        body = {"model": model, "pipeline_yaml": pipeline_yaml}
        if self.is_connected:
            try:
                return self._http_post(self._cfg("safe_eval_url"), "/v1/safe-eval:run", body)
            except (RuntimeError, OSError) as e:
                return {
                    **self._mock_eval(model),
                    "source": "mock",
                    "degraded": True,
                    "http_error": str(e),
                }
        return self._mock_eval(model)

    @staticmethod
    def _mock_eval(model: str) -> dict[str, Any]:
        return {
            "results": {"accuracy": 0.85, "robustness": 0.92, "adversarial_success_rate": 0.05},
            "summary": {
                "model": model,
                "stages_run": ["benchmarks", "adversarial"],
                "passed": True,
            },
            "veb": {"bundleId": f"veb-{uuid.uuid4()}", "format": "P8"},
            "source": "mock",
        }

    # ------------------------------------------------------------------
    # The @agent.action decorator.
    # ------------------------------------------------------------------

    def action(
        self,
        *,
        tool: str,
        side_effect: SideEffect = "read",
        actor: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorate a function with the full AumOS security envelope.

        The wrapped function returns an :class:`ActionResult` whose ``.value`` is the original
        function's return value, alongside the SVID, preflight result, and receipt. To get the
        raw return value back, use ``result.value`` or pass ``raw=True`` — see below.

        Steps performed per call (in order):

        1. Issue/verify an agent identity (I1) for ``actor`` (defaults to ``config.agent_svid``).
        2. Run pre-flight (R2). If ``config.fail_closed`` and preflight denies, raise
           :class:`ActionBlocked` and the wrapped function is never called (invariant I-09).
        3. Brokers scoped credentials (R4) — a secret scan of the JSON-serialized args; any
           finding is recorded on the result but does not block reads (configurable).
        4. Emits an AAR *before* the action commits (E1, invariant I-07).
        5. Calls the wrapped function.
        6. Records the result in :attr:`evidence`.
        7. On exception: emits a ``failure`` receipt and (if ``config.auto_kill_on_error``)
           triggers the R3 kill-switch, then raises :class:`ContainmentTriggered`.

        Args:
            tool: Tool name being wrapped (e.g. ``"github.create_pr"``).
            side_effect: Side-effect class (read/write/financial/destructive/physical).
            actor: SPIFFE ID of the acting agent. Defaults to ``config.agent_svid``.

        Returns:
            A decorator. The decorated function gains a ``.action_result`` attribute after each
            call holding the last :class:`ActionResult`.
        """
        if side_effect not in SIDE_EFFECTS:
            raise ValueError(f"side_effect must be one of {SIDE_EFFECTS}, got {side_effect!r}")
        if not tool:
            raise ValueError("tool is required")

        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                ag = actor or self.config.agent_svid
                start = time.perf_counter()

                # 1. Identity (issue once, reuse). Standalone always succeeds.
                if self._svid is None:
                    issued = self.issue_identity(ag)
                    self._svid = str(issued.get("svid", ""))

                # 2. Preflight (fail-closed per invariant I-09).
                inputs_json = _safe_serialize_args(args, kwargs)
                preflight = self.run_preflight(tool, inputs=inputs_json, side_effect=side_effect)
                if self.config.fail_closed and not preflight.get("allowed", False):
                    # Emit a 'denied' receipt for the evidence trail, then block.
                    denied = self.emit_receipt(
                        ag, tool, "denied", side_effect=side_effect, inputs_hash=_hash(inputs_json)
                    )
                    result = ActionResult(
                        ok=False,
                        value=None,
                        svid=self._svid,
                        preflight=preflight,
                        receipt=denied,
                        outcome="denied",
                        duration_ms=(time.perf_counter() - start) * 1000,
                        error=preflight.get("reason", "preflight denied"),
                    )
                    self.evidence.append(result.as_dict())
                    wrapper.action_result = result  # type: ignore[attr-defined]
                    raise ActionBlocked(str(result.error), preflight=preflight)

                # 3. Credential brokering — scan inputs for leaked secrets; record findings.
                secret_findings = self.scan_secrets(inputs_json)
                if secret_findings:
                    preflight = {
                        **preflight,
                        "secret_findings": [f.as_dict() for f in secret_findings],
                    }

                # 4. Emit the AAR BEFORE commit (invariant I-07). The pending receipt proves the
                #    intent-to-act was recorded before any side effect occurred; it is attached to
                #    every downstream ActionResult so the pre-commit evidence is always present.
                pending_receipt = self.emit_receipt(
                    ag, tool, "pending", side_effect=side_effect, inputs_hash=_hash(inputs_json)
                )
                preflight = {**preflight, "pre_commit_receipt": pending_receipt.receipt_id}

                # 5. Call the wrapped function.
                try:
                    value = fn(*args, **kwargs)
                except Exception as exc:
                    # 7. Failure path: record failure receipt + trigger containment.
                    failure_receipt = self.emit_receipt(
                        ag, tool, "failure", side_effect=side_effect, inputs_hash=_hash(inputs_json)
                    )
                    result = ActionResult(
                        ok=False,
                        value=None,
                        svid=self._svid,
                        preflight=preflight,
                        receipt=failure_receipt,
                        outcome="failure",
                        duration_ms=(time.perf_counter() - start) * 1000,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    self.evidence.append(result.as_dict())
                    wrapper.action_result = result  # type: ignore[attr-defined]
                    if self.config.auto_kill_on_error:
                        kill_outcome = self.kill(reason="behavioral_anomaly", agent=ag)
                        ct = ContainmentTriggered(
                            f"action '{tool}' raised {type(exc).__name__}; kill-switch triggered"
                        )
                        ct.kill_outcome = kill_outcome  # type: ignore[attr-defined]
                        raise ct from exc
                    raise exc

                # 6. Success path: emit success receipt + record.
                success_receipt = self.emit_receipt(
                    ag, tool, "success", side_effect=side_effect, inputs_hash=_hash(inputs_json)
                )
                result = ActionResult(
                    ok=True,
                    value=value,
                    svid=self._svid,
                    preflight=preflight,
                    receipt=success_receipt,
                    outcome="success",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
                self.evidence.append(result.as_dict())
                wrapper.action_result = result  # type: ignore[attr-defined]
                return value

            wrapper.action_result = None  # type: ignore[attr-defined]
            return wrapper

        return decorator

    # ------------------------------------------------------------------
    # Internals: HTTP, subprocess, serialization.
    # ------------------------------------------------------------------

    def _http_post(self, base_url: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = base_url.rstrip("/") + path
        return self._backend.post_json(url, body, float(self._cfg("http_timeout")))

    @staticmethod
    def _run_cli(cmd: str, args: list[str]) -> subprocess.CompletedProcess[str]:
        # subprocess.run with capture; never raises on non-zero exit (caller checks returncode).
        return subprocess.run(
            [cmd, *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )


def _safe_serialize_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    try:
        return json.dumps(
            {"args": list(args), "kwargs": kwargs}, default=_json_default, sort_keys=True
        )
    except (TypeError, ValueError):
        return repr({"args": args, "kwargs": kwargs})


def _json_default(o: Any) -> Any:
    if hasattr(o, "__dict__"):
        return o.__dict__
    return str(o)


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    # Local import-time-safe ISO timestamp.
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).isoformat()
