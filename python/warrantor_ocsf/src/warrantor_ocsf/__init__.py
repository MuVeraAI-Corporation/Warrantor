"""AumOS OCSF Forwarder.

Receives **AAR** (Agent Action Record) events from the E1 flight-recorder,
converts them to the [OCSF](https://schema.ocsf.io/) (Open Cybersecurity
Schema Framework) v1.1.0 format, and forwards them to one or more sinks
(Splunk HEC, Elastic, Datadog, or a local JSONL file for testing).

Mapping rules (per the OCSF schema):

- AAR / generic agent activity  -> ``class_uid 6003`` (API Activity),
  ``category_uid 6`` (Application Activity), ``activity_id 1`` (Access).
- Kill-switch trigger           -> ``class_uid 6007`` (Web Resources Activity
  extended for security response), ``severity_id 99`` (Critical) and
  ``activity_id 6`` (Detect).
- AAR with secret finding       -> ``class_uid 6003`` plus ``severity_id 90``
  (High) and a ``resources`` entry describing the exposed secret type.
- Attestation verification      -> ``class_uid 6003``, ``activity_id 5``
  (Authenticate), with ``user`` reflecting the verified identity.

Sinks implement the :class:`Sink` protocol: ``send(event: dict) -> bool``.
This package ships two concrete sinks:

- :class:`HTTPSink` — POSTs each OCSF event to a Splunk HEC / Elastic /
  Datadog endpoint with optional bearer token. Uses only the standard
  library.
- :class:`FileSink` — appends each event as one JSON line. Used in tests.

Usage:
    forwarder = OCSFForwarder()
    forwarder.add_sink(HTTPSink(url="https://splunk:8088/services/collector",
                                 token="..."))
    forwarder.add_sink(FileSink("/var/log/warrantor-ocsf.jsonl"))
    forwarder.forward(aar_event)
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# OCSF class/activity identifiers used by this forwarder.
# ---------------------------------------------------------------------------
CLASS_API_ACTIVITY = 6003  # API Activity
CLASS_SECURITY_RESPONSE = 6007  # Security Response
CATEGORY_APPLICATION = 6  # Application Activity
ACTIVITY_ACCESS = 1
ACTIVITY_AUTHENTICATE = 5
ACTIVITY_DETECT = 6

# OCSF severity_id mapping.
SEVERITY_INFO = 1
SEVERITY_LOW = 99  # informational-low per OCSF v1.1; we use INFO=1 above
SEVERITY_HIGH = 3
SEVERITY_CRITICAL = 5
# (OCSF: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical, 6/Fatal)

OCSF_VERSION = "1.1.0"


@runtime_checkable
class Sink(Protocol):
    """A sink that accepts a single OCSF event dict and reports success."""

    def send(self, event: dict) -> bool:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# OCSF conversion
# ---------------------------------------------------------------------------
def _iso(ts: float) -> str:
    """Render a unix timestamp as an ISO-8601 UTC string."""
    if not ts:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=UTC).isoformat().replace("+00:00", "Z")


def _pick_severity(aar: dict[str, Any]) -> int:
    """Pick OCSF severity_id for an AAR."""
    if aar.get("kill_switch_triggered"):
        return SEVERITY_CRITICAL
    if aar.get("secret_findings"):
        return SEVERITY_HIGH
    if aar.get("error"):
        return 3  # medium
    return SEVERITY_INFO


def _build_message(aar: dict[str, Any]) -> str:
    parts: list[str] = []
    action = aar.get("action_type") or aar.get("type") or "activity"
    name = aar.get("action_name") or aar.get("name") or ""
    parts.append(f"AAR {action}:{name}")
    identity = aar.get("identity") or "anonymous"
    parts.append(f"identity={identity}")
    if aar.get("kill_switch_triggered"):
        parts.append("KILL_SWITCH")
    findings = aar.get("secret_findings") or []
    if findings:
        parts.append("secrets=" + ",".join(findings))
    if aar.get("error"):
        parts.append(f"error={aar['error']}")
    return " ".join(parts)


def convert_aar_to_ocsf(aar: dict[str, Any]) -> dict[str, Any]:
    """Convert a single AAR dict to an OCSF API-Activity event.

    The function tolerates missing fields: AARs produced by the in-process
    harness (``warrantor_langchain.AAR.to_dict()``) are richer than the minimum
    this function needs, and the E1 log may emit slimmer dicts. Either way we
    always produce a structurally valid OCSF event with ``class_uid 6003``.
    """
    if not isinstance(aar, dict):
        raise TypeError("aar must be a dict")

    aar_id = str(aar.get("aar_id") or aar.get("id") or uuid.uuid4().hex)
    ts = float(aar.get("completed_at") or aar.get("timestamp") or time.time())
    severity = _pick_severity(aar)

    # Kill-switch events upgrade to class 6007 (Security Response).
    if aar.get("kill_switch_triggered"):
        class_uid = CLASS_SECURITY_RESPONSE
        activity_id = ACTIVITY_DETECT
    else:
        class_uid = CLASS_API_ACTIVITY
        activity_id = (
            ACTIVITY_AUTHENTICATE if aar.get("action_type") == "attestation" else ACTIVITY_ACCESS
        )

    identity = str(aar.get("identity") or "anonymous")
    action_name = str(aar.get("action_name") or aar.get("name") or "unknown")
    side_effect = str(aar.get("side_effect_class") or "read")

    resources: list[dict[str, Any]] = []
    findings = aar.get("secret_findings") or []
    for finding in findings:
        resources.append(
            {
                "type": "credential",
                "name": str(finding),
                "uid": f"secret:{finding}",
            }
        )

    event: dict[str, Any] = {
        "$schema": "https://schema.ocsf.io/" + OCSF_VERSION,
        "version": OCSF_VERSION,
        "class_uid": class_uid,
        "category_uid": CATEGORY_APPLICATION,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity,
        "status": "Success" if not aar.get("error") else "Failure",
        "status_id": 1 if not aar.get("error") else 2,
        "time": int(ts),
        "time_dt": _iso(ts),
        "message": _build_message(aar),
        "metadata": {
            "product": {"name": "AumOS", "vendor_name": "MuVera AI"},
            "version": "1.0.0",
            "log_source": "aumos.e1",
            "original_time": aar_id,
        },
        "actor": {
            "user": {
                "uid": identity,
                "name": identity,
            },
            "invoked_by": "warrantor-agent",
        },
        "api": {
            "operation": action_name,
            "request": {
                "uid": aar_id,
                "data": aar.get("inputs") or {},
            },
            "response": {
                "code": 0 if not aar.get("error") else 500,
                "data": aar.get("outputs") or {},
            },
        },
        "resources": resources,
        "unmapped": {
            "side_effect_class": side_effect,
            "started_at": aar.get("started_at"),
            "duration_ms": aar.get("duration_ms"),
        },
    }
    return event


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------
class FileSink:
    """Append each OCSF event as one JSON line in ``path``.

    Thread-safe. Creates the file (and parent directories) on first write.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = str(path)
        self._lock = threading.Lock()

    def send(self, event: dict) -> bool:
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event, sort_keys=True, default=str)
            with self._lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            return True
        except OSError:
            return False


class HTTPSink:
    """POST each OCSF event to an HTTP endpoint (Splunk HEC / Elastic / Datadog).

    Parameters:
        url:      full endpoint URL (e.g. ``https://splunk:8088/services/collector``).
        token:    optional bearer / Splunk HEC token.
        timeout:  per-request timeout in seconds.
        encoder:  optional callable that wraps ``event`` in the format the
                  backend expects. Default = identity (raw OCSF JSON).
    """

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        timeout: float = 5.0,
        encoder: Any = None,
    ) -> None:
        if not url:
            raise ValueError("url must be a non-empty string")
        self.url = url
        self.token = token
        self.timeout = timeout
        self.encoder = encoder or (lambda e: e)

    def send(self, event: dict) -> bool:
        import urllib.error
        import urllib.request

        payload = self.encoder(event)
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(
            self.url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, TimeoutError):
            return False


class _CountingSink:
    """Test-only sink that records everything and always succeeds."""

    def __init__(self, *, succeed: bool = True) -> None:
        self.events: list[dict] = []
        self.succeed = succeed

    def send(self, event: dict) -> bool:
        self.events.append(event)
        return self.succeed


# ---------------------------------------------------------------------------
# Forwarder
# ---------------------------------------------------------------------------
@dataclass
class ForwardStats:
    """Per-forwarder counters."""

    forwarded: int = 0
    succeeded: int = 0
    failed: int = 0


@dataclass
class OCSFForwarder:
    """Convert AAR events to OCSF and ship them to configured sinks.

    Sinks are tried in registration order. A sink that returns ``False`` (or
    raises) counts as a failure but does **not** abort delivery to the
    remaining sinks, so a flaky SIEM cannot block a healthy one.
    """

    sinks: list[Sink] = field(default_factory=list)
    stats: ForwardStats = field(default_factory=ForwardStats)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add_sink(self, sink: Sink) -> None:
        """Register ``sink``. Order matters: sinks are tried in registration order."""
        if not hasattr(sink, "send"):
            raise TypeError("sink must implement send(event: dict) -> bool")
        self.sinks.append(sink)

    def convert(self, aar_event: dict[str, Any]) -> dict[str, Any]:
        """Convert a single AAR to OCSF without forwarding. (Useful in tests.)"""
        return convert_aar_to_ocsf(aar_event)

    def forward(self, aar_event: dict[str, Any]) -> bool:
        """Convert and forward a single AAR.

        Returns ``True`` if at least one sink accepted the event, ``False``
        otherwise (including when no sinks are registered).
        """
        ocsf = convert_aar_to_ocsf(aar_event)
        any_ok = False
        with self._lock:
            sinks = list(self.sinks)
        for sink in sinks:
            try:
                ok = bool(sink.send(ocsf))
            except Exception:
                ok = False
            if ok:
                any_ok = True
        with self._lock:
            self.stats.forwarded += 1
            if any_ok:
                self.stats.succeeded += 1
            else:
                self.stats.failed += 1
        return any_ok

    def batch_forward(self, events: list[dict[str, Any]]) -> int:
        """Forward a batch. Returns the number of events accepted by >=1 sink."""
        accepted = 0
        for event in events:
            if self.forward(event):
                accepted += 1
        return accepted

    def reset_stats(self) -> None:
        with self._lock:
            self.stats = ForwardStats()


__all__ = [
    "ACTIVITY_ACCESS",
    "ACTIVITY_AUTHENTICATE",
    "ACTIVITY_DETECT",
    "CATEGORY_APPLICATION",
    "CLASS_API_ACTIVITY",
    "CLASS_SECURITY_RESPONSE",
    "OCSF_VERSION",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_INFO",
    "FileSink",
    "ForwardStats",
    "HTTPSink",
    "OCSFForwarder",
    "Sink",
    "convert_aar_to_ocsf",
]
