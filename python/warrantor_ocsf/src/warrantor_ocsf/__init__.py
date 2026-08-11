"""AumOS OCSF Forwarder.

Receives **AAR** (Agent Action Record) events from the E1 flight-recorder,
converts them to the [OCSF](https://schema.ocsf.io/) (Open Cybersecurity
Schema Framework) v1.9.0 format, and forwards them to one or more sinks
(Splunk HEC, Elastic, Datadog, or a local JSONL file for testing).

Every event is ``class_uid 6003`` (API Activity) in ``category_uid 6``
(Application Activity). ``activity_id`` comes from the AAR's
``side_effect_class`` and must be one of the six values OCSF defines for this
class -- ``0`` Unknown, ``1`` Create, ``2`` Read, ``3`` Update, ``4`` Delete,
``99`` Other:

- read / none            -> ``2`` (Read)
- write / create/ append -> ``1`` (Create)
- update / modify        -> ``3`` (Update)
- delete / destroy       -> ``4`` (Delete)
- attestation, anything else -> ``99`` (Other)

Significance is carried by ``severity_id`` (OCSF: 1 Informational, 2 Low,
3 Medium, 4 High, 5 Critical), not by the class:

- kill-switch trigger  -> ``5`` (Critical)
- secret finding       -> ``4`` (High), plus a ``resources`` entry naming the
  exposed credential type
- tool error           -> ``3`` (Medium)
- everything else      -> ``1`` (Informational)

Events are validated against the published schema by
``tools/audit/ocsf_validate.py``; ``tests/test_ocsf_schema.py`` pins the same
invariants offline so CI does not depend on the network.

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
CATEGORY_APPLICATION = 6  # Application Activity

# OCSF 6003 activity_id enum -- the ONLY values the schema defines. Every agent action is one of
# these; there is no "Access" and no "Authenticate". Inventing members (this module previously used
# 5 and 6) makes the event fail validation and land in the SIEM's parse-error queue.
ACTIVITY_UNKNOWN = 0
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_OTHER = 99

#: The AAR already carries the discriminator OCSF's enum wants. Use it rather than hard-coding.
_ACTIVITY_BY_SIDE_EFFECT = {
    "read": ACTIVITY_READ,
    "none": ACTIVITY_READ,
    "write": ACTIVITY_CREATE,
    "create": ACTIVITY_CREATE,
    "append": ACTIVITY_CREATE,
    "update": ACTIVITY_UPDATE,
    "modify": ACTIVITY_UPDATE,
    "delete": ACTIVITY_DELETE,
    "destroy": ACTIVITY_DELETE,
}

# OCSF severity_id enum (schema.ocsf.io): 0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High,
# 5=Critical, 6=Fatal, 99=Other. The previous values (HIGH=3, LOW=99) meant a secret exposure was
# reported as "Medium" -- indistinguishable from an ordinary tool error.
SEVERITY_UNKNOWN = 0
SEVERITY_INFO = 1
SEVERITY_LOW = 2
SEVERITY_MEDIUM = 3
SEVERITY_HIGH = 4
SEVERITY_CRITICAL = 5

#: The OCSF schema version these events declare in ``metadata.version``. Events are validated
#: against this version by ``tools/audit/ocsf_validate.py``; declaring an older version than we
#: actually target makes every consumer's validator emit version-skew warnings.
OCSF_VERSION = "1.9.0"

#: This forwarder's own version, reported as ``metadata.product.version``. Distinct from
#: OCSF_VERSION: one describes the schema, the other the producer.
PRODUCT_VERSION = "1.0.0"


@runtime_checkable
class Sink(Protocol):
    """A sink that accepts a single OCSF event dict and reports success."""

    def send(self, event: dict) -> bool:  # pragma: no cover - protocol
        ...


# ---------------------------------------------------------------------------
# OCSF conversion
# ---------------------------------------------------------------------------
def _iso(ts: float) -> str:
    """Render a unix timestamp (seconds) as an ISO-8601 UTC string."""
    if not ts:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=UTC).isoformat().replace("+00:00", "Z")


def _coerce_ts(value: Any) -> float | None:
    """Best-effort conversion of an AAR timestamp to unix seconds.

    AARs reach us from several producers, and they do not agree on a format: the in-process
    harness emits a float, while records replayed from the E1 log carry ISO-8601 strings. A bare
    ``float()`` raised ValueError on the latter -- and because the conversion happened outside
    ``forward``'s try block, one such record aborted an entire batch.

    Returns ``None`` when the value is absent or uninterpretable, so the caller can fall back to
    the current time rather than fail.
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):  # bool is an int subclass; never a timestamp
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        # fromisoformat handles "+00:00"; normalise the "Z" suffix it rejects on older versions.
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp()


def _pick_severity(aar: dict[str, Any]) -> int:
    """Pick OCSF severity_id for an AAR."""
    if aar.get("kill_switch_triggered"):
        return SEVERITY_CRITICAL
    if aar.get("secret_findings"):
        # High, not Medium: a leaked credential must be distinguishable from a tool error.
        return SEVERITY_HIGH
    if aar.get("error"):
        return SEVERITY_MEDIUM
    return SEVERITY_INFO


def _pick_activity(aar: dict[str, Any]) -> int:
    """Map an AAR to one of OCSF 6003's six defined activity_id values."""
    if aar.get("action_type") == "attestation":
        # OCSF 6003 has no Authenticate activity. "Other" is the honest mapping: calling an
        # attestation verification a "Read" would mislabel a security control as a data access.
        # Class 3002 (Authentication) is the correct long-term home for these events.
        return ACTIVITY_OTHER
    side_effect = str(aar.get("side_effect_class") or "").strip().lower()
    if not side_effect:
        # No side_effect_class at all: we have no information about what the action did. That is
        # what OCSF's "Unknown" means -- distinct from "Other", which asserts the action does not
        # fit any defined category.
        return ACTIVITY_UNKNOWN
    return _ACTIVITY_BY_SIDE_EFFECT.get(side_effect, ACTIVITY_OTHER)


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
    ts = _coerce_ts(aar.get("completed_at"))
    if ts is None:
        ts = _coerce_ts(aar.get("timestamp"))
    if ts is None:
        ts = time.time()
    severity = _pick_severity(aar)

    # Every event is API Activity (6003). Kill-switch events were previously emitted as class
    # 6007 -- which is Scan Activity, not "Security Response". That class defines no actor, api or
    # resources attribute, so the entire security payload was silently discarded by the schema and
    # the event failed validation for a missing `scan` object it could never have. A kill-switch
    # trigger is an API action taken by an agent, so it belongs here, distinguished by Critical
    # severity and the `is_alert` flag rather than by a class that does not describe it.
    class_uid = CLASS_API_ACTIVITY
    activity_id = _pick_activity(aar)

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
        "class_uid": class_uid,
        "category_uid": CATEGORY_APPLICATION,
        "activity_id": activity_id,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity,
        "status": "Success" if not aar.get("error") else "Failure",
        "status_id": 1 if not aar.get("error") else 2,
        # OCSF timestamp_t is MILLISECONDS since the epoch. Emitting seconds put every event in
        # January 1970, where retention rules and time-range searches never found them. Both time
        # fields derive from the same `ts` so they cannot drift apart.
        "time": int(ts * 1000),
        "message": _build_message(aar),
        # What tells a SIEM "this one needs a human" is severity_id: Critical for a kill-switch
        # trigger, High for a secret exposure. (OCSF's dedicated `is_alert` flag only exists from
        # schema 1.2 onward, so it cannot be emitted while we declare 1.1.0.)
        "metadata": {
            # metadata.version is the OCSF *schema* version; the product's own version belongs
            # under product.version. Conflating them told consumers we spoke schema 1.0.0.
            "version": OCSF_VERSION,
            "product": {
                "name": "AumOS",
                "vendor_name": "MuVera AI",
                "version": PRODUCT_VERSION,
            },
            "log_name": "warrantor.e1",
            # The AAR id is the correlation key back to the flight recorder. It was previously
            # stuffed into `original_time`, which is neither valid here nor a time.
            "uid": aar_id,
            "correlation_uid": aar_id,
            "logged_time": int(time.time() * 1000),
            "original_time": _iso(ts),
        },
        "actor": {
            "user": {
                "uid": identity,
                "name": identity,
            },
            # `actor.app_name` is deprecated as of OCSF 1.9 in favour of `actor.application`.
            "application": {"name": "warrantor-agent"},
        },
        # src_endpoint is required by the class. We do not observe a network peer for an
        # in-process agent action, so name the producing component rather than omit the field.
        "src_endpoint": {
            "svc_name": "warrantor-agent",
            "hostname": str(aar.get("host") or "localhost"),
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
            "kill_switch_triggered": bool(aar.get("kill_switch_triggered")),
            "action_type": aar.get("action_type"),
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
        # `default=str` matches FileSink. Without it, an AAR carrying a datetime (or any
        # non-JSON-native value) raised TypeError here -- outside the try below, so it
        # escaped to the caller, which counted the send as merely "not accepted". With a
        # FileSink also registered, the file write succeeded, `forward()` returned True and
        # the stats read succeeded=1, while the SIEM received nothing at all.
        body = json.dumps(payload, default=str).encode("utf-8")
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
#: Cap on retained per-sink error samples, so a persistently broken sink cannot grow this
#: list without bound in a long-running forwarder.
_MAX_RECENT_SINK_ERRORS = 20


@dataclass
class ForwardStats:
    """Per-forwarder counters.

    ``succeeded`` means *at least one* sink accepted the event, so it is not evidence that
    any particular sink is healthy. Use ``sink_failures`` for that: a SIEM sink that never
    receives an event while a file sink keeps working shows up there and nowhere else.
    """

    forwarded: int = 0
    succeeded: int = 0
    failed: int = 0
    #: Total per-sink rejections and exceptions, counted even when another sink succeeded.
    sink_failures: int = 0
    #: Events that could not be converted to OCSF at all. These never reached a sink, so they are
    #: invisible in ``sink_failures``; a non-zero value here means AARs are being dropped upstream
    #: of delivery.
    conversion_failures: int = 0
    #: A bounded sample of recent per-sink failure descriptions, for diagnosis.
    recent_sink_errors: list[str] = field(default_factory=list)


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
        # Conversion runs inside the accounting path. It used to happen before it, so a single
        # malformed AAR raised straight out of forward(), aborted the enclosing batch_forward
        # loop, and left every remaining event undelivered AND uncounted -- stats reported a 100%
        # success rate while most of the batch was lost. A record we cannot convert is a failure,
        # not an absence.
        try:
            ocsf = convert_aar_to_ocsf(aar_event)
        except Exception as error:
            with self._lock:
                self.stats.forwarded += 1
                self.stats.failed += 1
                self.stats.conversion_failures += 1
                detail = f"convert: {type(error).__name__}: {error}"
                if len(self.stats.recent_sink_errors) < _MAX_RECENT_SINK_ERRORS:
                    self.stats.recent_sink_errors.append(detail)
            return False

        any_ok = False
        failures: list[str] = []
        with self._lock:
            sinks = list(self.sinks)
        for sink in sinks:
            name = type(sink).__name__
            try:
                ok = bool(sink.send(ocsf))
                if not ok:
                    failures.append(f"{name}: rejected the event")
            # Broad by design: one sink must never prevent the others from receiving
            # the event, and the failure is recorded rather than swallowed.
            except Exception as error:
                ok = False
                failures.append(f"{name}: {type(error).__name__}: {error}")
            if ok:
                any_ok = True
        with self._lock:
            self.stats.forwarded += 1
            if any_ok:
                self.stats.succeeded += 1
            else:
                self.stats.failed += 1
            # Per-sink failures are recorded even when another sink succeeded.
            #
            # `any_ok` alone hid a permanently-broken SIEM: with a FileSink and an HTTPSink
            # registered, the file write made forward() return True and stats read
            # succeeded=1 while the SIEM received nothing. For a security-event forwarder
            # that is the worst possible failure -- the events stop arriving and every
            # health signal stays green.
            for detail in failures:
                self.stats.sink_failures += 1
                if len(self.stats.recent_sink_errors) < _MAX_RECENT_SINK_ERRORS:
                    self.stats.recent_sink_errors.append(detail)
        return any_ok

    def batch_forward(self, events: list[dict[str, Any]]) -> int:
        """Forward a batch. Returns the number of events accepted by >=1 sink.

        Every event is attempted. One unconvertible record does not stop the rest: in a security
        pipeline, a poison record must cost you that record, not the batch behind it.
        """
        accepted = 0
        for event in events:
            if self.forward(event):
                accepted += 1
        return accepted

    def reset_stats(self) -> None:
        with self._lock:
            self.stats = ForwardStats()


__all__ = [
    "ACTIVITY_CREATE",
    "ACTIVITY_DELETE",
    "ACTIVITY_OTHER",
    "ACTIVITY_READ",
    "ACTIVITY_UNKNOWN",
    "ACTIVITY_UPDATE",
    "CATEGORY_APPLICATION",
    "CLASS_API_ACTIVITY",
    "OCSF_VERSION",
    "PRODUCT_VERSION",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_INFO",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_UNKNOWN",
    "FileSink",
    "ForwardStats",
    "HTTPSink",
    "OCSFForwarder",
    "Sink",
    "convert_aar_to_ocsf",
]
