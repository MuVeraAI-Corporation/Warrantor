"""AumOS Jira/Linear incident forwarder.

Auto-creates tickets in Jira or Linear from AumOS agent incidents (P9 / X9).
The forwarder consumes the normalised incident dict shape produced by
``incident_exchange`` and maps AumOS incident types to ticket labels and
priorities.

Three forwarders are provided with a common interface:

  * :class:`JiraForwarder`  — Jira Cloud REST API (or incoming webhook).
  * :class:`LinearForwarder` — Linear GraphQL API.
  * :class:`MockForwarder`  — in-memory store for tests and local development,
                              no API key required.

All three implement the same four methods so callers can swap implementations
by configuration::

    fwd = JiraForwarder(webhook_url=..., api_token=...)   # production
    fwd = MockForwarder()                                  # tests / dry-run

    ticket = fwd.create_ticket(incident_dict)
    fwd.update_ticket(ticket.ticket_id, "in progress")
    fwd.close_ticket(ticket.ticket_id, "mitigated")

Incident dict shape (subset; extra keys are ignored)::

    {
      "incident_id": "inc-123",
      "incident_type": "goal_hijack" | "exfiltration" | ...,
      "severity": "low" | "medium" | "high" | "critical",
      "summary": "short one-line description",
      "details": "long-form findings",
      "agent_id": "spiffe://muveraai.com/agent/x",
      "detected_at": 1700000000.0,
    }

Incident-type → label / priority mapping (per AumOS X9):

    goal_hijack           → security/critical
    exfiltration          → security/high
    identity_compromise   → security/high
    rogue_delegation      → security/medium
    tool_abuse            → security/medium
    memory_poisoning      → security/medium
    <unknown>             → security/low
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol
from urllib import error as urlerror
from urllib import request as urlrequest

__all__ = [
    "DEFAULT_PROJECT_KEY",
    "INCIDENT_LABELS",
    "INCIDENT_PRIORITIES",
    "IncidentForwarderError",
    "IncidentTicket",
    "JiraForwarder",
    "LinearForwarder",
    "MockForwarder",
    "TicketForwarder",
]


class IncidentForwarderError(Exception):
    """Raised when an incident cannot be forwarded to the ticketing system."""


# Default Jira project key. Override per-deployment via the constructor.
DEFAULT_PROJECT_KEY = "AUMOS"

# AumOS incident type → ticket label (X9 mapping). See docs/rfcs/X9.
INCIDENT_LABELS: dict[str, str] = {
    "goal_hijack": "security/critical",
    "exfiltration": "security/high",
    "identity_compromise": "security/high",
    "rogue_delegation": "security/medium",
    "tool_abuse": "security/medium",
    "memory_poisoning": "security/medium",
}

# AumOS incident type → Jira priority name. Linear uses a separate priority
# mapping (Linear priorities are team-configured UUIDs); we send the severity
# string and let the LinearForwarder translate.
INCIDENT_PRIORITIES: dict[str, str] = {
    "goal_hijack": "Highest",
    "exfiltration": "High",
    "identity_compromise": "High",
    "rogue_delegation": "Medium",
    "tool_abuse": "Medium",
    "memory_poisoning": "Medium",
}

# AumOS severity (from the incident dict) → Jira priority. Used as a fallback
# when incident_type is unknown.
SEVERITY_TO_JIRA_PRIORITY: dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def label_for(incident_type: str | None) -> str:
    """Return the Jira/Linear label for an AumOS incident type."""
    if incident_type is None:
        return "security/low"
    return INCIDENT_LABELS.get(incident_type, "security/low")


def priority_for(incident_type: str | None, severity: str | None = None) -> str:
    """Return the Jira priority for an incident, falling back to severity."""
    if incident_type and incident_type in INCIDENT_PRIORITIES:
        return INCIDENT_PRIORITIES[incident_type]
    if severity and severity in SEVERITY_TO_JIRA_PRIORITY:
        return SEVERITY_TO_JIRA_PRIORITY[severity]
    return "Medium"


@dataclass
class IncidentTicket:
    """A ticket created in the target system from an AumOS incident.

    Attributes:
        ticket_id:    the remote system's identifier (Jira issue key like
                      ``AUMOS-123``, Linear UUID, or a synthetic id for the
                      MockForwarder).
        title:        one-line summary used as the ticket summary.
        description:  long-form description.
        severity:     the AumOS severity that was forwarded (low/medium/high/critical).
        status:       current ticket status (open/in progress/resolved/closed...).
        labels:       list of labels applied (e.g. ``["security/critical"]``).
        incident_id:  the originating AumOS incident id (for traceability).
        url:          optional link to the ticket in the target system.
        created_at:   POSIX timestamp the ticket was created.
    """

    ticket_id: str
    title: str
    description: str
    severity: str
    status: str = "open"
    labels: list[str] = field(default_factory=list)
    incident_id: str | None = None
    url: str | None = None
    created_at: float = field(default_factory=time.time)


class TicketForwarder(Protocol):
    """Common interface implemented by all forwarders."""

    def create_ticket(self, incident: dict[str, Any]) -> IncidentTicket: ...

    def update_ticket(self, ticket_id: str, status: str) -> IncidentTicket: ...

    def close_ticket(self, ticket_id: str, resolution: str) -> IncidentTicket: ...


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require(incident: dict[str, Any], key: str) -> Any:
    if key not in incident:
        raise IncidentForwarderError(f"incident dict missing required field {key!r}")
    return incident[key]


def _build_title(incident: dict[str, Any]) -> str:
    summary = incident.get("summary") or incident.get("title")
    if summary:
        return str(summary)
    itype = incident.get("incident_type", "unknown")
    iid = incident.get("incident_id", "?")
    return f"[AumOS] {itype} incident {iid}"


def _build_description(incident: dict[str, Any]) -> str:
    parts: list[str] = []
    details = incident.get("details") or incident.get("description") or ""
    if details:
        parts.append(str(details))
    agent = incident.get("agent_id")
    if agent:
        parts.append(f"\nAgent: {agent}")
    detected = incident.get("detected_at")
    if detected is not None:
        parts.append(f"Detected at: {detected}")
    atlas = incident.get("atlas_techniques") or incident.get("mitre_atlas")
    if atlas:
        parts.append(f"MITRE ATLAS: {atlas}")
    return "\n".join(parts).strip() or "(no details provided)"


# ---------------------------------------------------------------------------
# JiraForwarder
# ---------------------------------------------------------------------------


class JiraForwarder:
    """Forward AumOS incidents to Jira Cloud.

    Two transports are supported, selected by constructor arguments:

      * **REST API** — pass ``base_url`` (e.g. ``https://yourorg.atlassian.net``)
        + ``api_token`` + ``user_email``. ``create_ticket`` POSTs to
        ``/rest/api/3/issue``.
      * **Incoming webhook** — pass only ``webhook_url``. ``create_ticket`` POSTs
        the incident summary to the webhook (Jira treats the webhook payload
        shape per the configured automation; this forwarder sends the same
        JSON document the REST path would send, plus the originating incident).

    The HTTP layer is the standard-library ``urllib`` so this module has **no
    third-party dependencies**. The actual HTTP call is isolated in
    :meth:`_post` so tests can monkeypatch it.
    """

    def __init__(
        self,
        *,
        webhook_url: str | None = None,
        base_url: str | None = None,
        api_token: str | None = None,
        user_email: str | None = None,
        project_key: str = DEFAULT_PROJECT_KEY,
        timeout: float = 15.0,
    ) -> None:
        if not webhook_url and not (base_url and api_token):
            raise IncidentForwarderError(
                "JiraForwarder requires either webhook_url or (base_url + api_token)"
            )
        self.webhook_url = webhook_url
        self.base_url = base_url.rstrip("/") if base_url else None
        self.api_token = api_token
        self.user_email = user_email
        self.project_key = project_key or DEFAULT_PROJECT_KEY
        self.timeout = timeout

    # -- public API ----------------------------------------------------

    def create_ticket(self, incident: dict[str, Any]) -> IncidentTicket:
        _require(incident, "incident_id")
        itype = incident.get("incident_type")
        severity = str(incident.get("severity", "medium"))
        labels = [label_for(itype)]
        # Always tag with the aumos incident-id label for filtering.
        labels.append(f"warrantor-incident/{incident['incident_id']}")
        title = _build_title(incident)
        description = _build_description(incident)
        payload = self._issue_payload(title, description, labels, itype, severity, incident)
        resp = self._post(self._create_endpoint(), payload)
        ticket_id = str(resp.get("key") or resp.get("id") or self._synthetic_id(incident))
        url = resp.get("self") or (f"{self.base_url}/browse/{ticket_id}" if self.base_url else None)
        return IncidentTicket(
            ticket_id=ticket_id,
            title=title,
            description=description,
            severity=severity,
            status="open",
            labels=labels,
            incident_id=str(incident["incident_id"]),
            url=url,
        )

    def update_ticket(self, ticket_id: str, status: str) -> IncidentTicket:
        endpoint = self._transition_endpoint(ticket_id)
        self._post(endpoint, {"status": status})
        return IncidentTicket(
            ticket_id=ticket_id,
            title="(updated)",
            description="",
            severity="medium",
            status=status,
        )

    def close_ticket(self, ticket_id: str, resolution: str) -> IncidentTicket:
        endpoint = self._transition_endpoint(ticket_id)
        self._post(endpoint, {"status": "closed", "resolution": resolution})
        return IncidentTicket(
            ticket_id=ticket_id,
            title="(closed)",
            description="",
            severity="medium",
            status="closed",
        )

    # -- payload / endpoints -------------------------------------------

    def _issue_payload(
        self,
        title: str,
        description: str,
        labels: list[str],
        incident_type: str | None,
        severity: str,
        incident: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": title,
                "description": description,
                "issuetype": {"name": "Incident"},
                "labels": labels,
                "priority": {"name": priority_for(incident_type, severity)},
                "customfield_aumos_incident_id": incident.get("incident_id"),
                "customfield_aumos_incident_type": incident_type,
            }
        }

    def _create_endpoint(self) -> str:
        if self.webhook_url and not self.base_url:
            return self.webhook_url
        return f"{self.base_url}/rest/api/3/issue"

    def _transition_endpoint(self, ticket_id: str) -> str:
        if self.webhook_url and not self.base_url:
            return self.webhook_url
        return f"{self.base_url}/rest/api/3/issue/{ticket_id}/transitions"

    def _synthetic_id(self, incident: dict[str, Any]) -> str:
        return f"{self.project_key}-{abs(hash(incident['incident_id'])) % 10000}"

    # -- HTTP (isolated for monkeypatching) ----------------------------

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = urlrequest.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        if self.api_token:
            # Jira Cloud uses Basic auth with email:api_token.
            import base64

            creds = f"{self.user_email or ''}:{self.api_token}".encode()
            req.add_header("Authorization", "Basic " + base64.b64encode(creds).decode("ascii"))
        try:
            with urlrequest.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urlerror.HTTPError as e:
            raise IncidentForwarderError(f"Jira HTTP {e.code}: {e.reason}") from e
        except urlerror.URLError as e:
            raise IncidentForwarderError(f"Jira network error: {e.reason}") from e
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
        return parsed if isinstance(parsed, dict) else {"raw": parsed}


# ---------------------------------------------------------------------------
# LinearForwarder
# ---------------------------------------------------------------------------


class LinearForwarder:
    """Forward AumOS incidents to Linear via its GraphQL API.

    Uses a single Linear API key (``api_token``). ``create_ticket`` runs an
    ``issueCreate`` mutation. The HTTP layer is again stdlib ``urllib``,
    isolated in :meth:`_graphql` so tests can monkeypatch it.

    Linear priorities are team-configured UUIDs; this forwarder sends the
    integer priority 0..4 derived from the AumOS severity (urgent=4 .. low=0)
    which is Linear's default schema.
    """

    GRAPHQL_URL = "https://api.linear.app/graphql"

    SEVERITY_TO_LINEAR_PRIORITY: ClassVar[dict[str, int]] = {
        "critical": 4,  # Urgent
        "high": 3,  # High
        "medium": 2,  # Medium
        "low": 1,  # Low
    }

    def __init__(
        self,
        *,
        api_token: str,
        team_id: str,
        project_id: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        if not api_token or not team_id:
            raise IncidentForwarderError("LinearForwarder requires api_token and team_id")
        self.api_token = api_token
        self.team_id = team_id
        self.project_id = project_id
        self.timeout = timeout

    def create_ticket(self, incident: dict[str, Any]) -> IncidentTicket:
        _require(incident, "incident_id")
        itype = incident.get("incident_type")
        severity = str(incident.get("severity", "medium"))
        labels = [label_for(itype), f"warrantor-incident/{incident['incident_id']}"]
        title = _build_title(incident)
        description = _build_description(incident)
        mutation = self._create_mutation(
            title, description, labels, self._priority(severity), incident
        )
        resp = self._graphql(mutation)
        node = resp.get("data", {}).get("issueCreate", {}).get("issue", {})
        ticket_id = str(node.get("id") or node.get("identifier") or uuid.uuid4().hex)
        url = node.get("url")
        return IncidentTicket(
            ticket_id=ticket_id,
            title=title,
            description=description,
            severity=severity,
            status="open",
            labels=labels,
            incident_id=str(incident["incident_id"]),
            url=url,
        )

    def update_ticket(self, ticket_id: str, status: str) -> IncidentTicket:
        state_id = self._state_id_for(status)
        mutation = (
            f"mutation {{ issueUpdate(id: {json.dumps(ticket_id)}, "
            f"input: {{stateId: {json.dumps(state_id)}}}) {{ success }} }}"
        )
        self._graphql(mutation)
        return IncidentTicket(
            ticket_id=ticket_id,
            title="(updated)",
            description="",
            severity="medium",
            status=status,
        )

    def close_ticket(self, ticket_id: str, resolution: str) -> IncidentTicket:
        desc = f"Resolved: {resolution}"
        mutation = (
            f"mutation {{ issueUpdate(id: {json.dumps(ticket_id)}, "
            f'input: {{stateId: "closed", description: {json.dumps(desc)}}}) {{ success }} }}'
        )
        self._graphql(mutation)
        return IncidentTicket(
            ticket_id=ticket_id,
            title="(closed)",
            description="",
            severity="medium",
            status="closed",
        )

    # -- helpers -------------------------------------------------------

    def _priority(self, severity: str) -> int:
        return self.SEVERITY_TO_LINEAR_PRIORITY.get(severity, 2)

    def _state_id_for(self, status: str) -> str:
        # Linear state ids are team-specific; we forward the requested status
        # string as a sentinel and let the caller's team config map it. For the
        # common cases we use well-known default names.
        mapping = {
            "open": "started",
            "in progress": "started",
            "started": "started",
            "resolved": "completed",
            "closed": "canceled",
        }
        return mapping.get(status.lower(), status.lower())

    def _create_mutation(
        self,
        title: str,
        description: str,
        labels: list[str],
        priority: int,
        incident: dict[str, Any],
    ) -> str:
        # Build a GraphQL mutation. We keep it as a string (Linear accepts
        # string queries); variables are inlined with JSON-escaped literals.
        title_json = json.dumps(title)
        desc_json = json.dumps(description)
        labels_json = json.dumps(labels)
        team_json = json.dumps(self.team_id)
        project_clause = f", projectId: {json.dumps(self.project_id)}" if self.project_id else ""
        return (
            "mutation { issueCreate(input: {"
            f"teamId: {team_json}, title: {title_json}, "
            f"description: {desc_json}, priority: {priority}, "
            f"labels: {labels_json}{project_clause}"
            "}) { issue { id identifier url } success } }"
        )

    def _graphql(self, query: str) -> dict[str, Any]:
        body = json.dumps({"query": query}).encode("utf-8")
        req = urlrequest.Request(self.GRAPHQL_URL, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", self.api_token)
        try:
            with urlrequest.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urlerror.HTTPError as e:
            raise IncidentForwarderError(f"Linear HTTP {e.code}: {e.reason}") from e
        except urlerror.URLError as e:
            raise IncidentForwarderError(f"Linear network error: {e.reason}") from e
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
        return parsed if isinstance(parsed, dict) else {"raw": parsed}


# ---------------------------------------------------------------------------
# MockForwarder
# ---------------------------------------------------------------------------


class MockForwarder:
    """In-memory forwarder for tests and local development.

    Implements the same interface as :class:`JiraForwarder` /
    :class:`LinearForwarder` but stores tickets in a dict instead of calling
    any HTTP API. Useful for dry-runs, unit tests, and CI.
    """

    def __init__(self, *, project_key: str = DEFAULT_PROJECT_KEY) -> None:
        self.project_key = project_key
        self.tickets: dict[str, IncidentTicket] = {}
        self._counter = 0
        # Captures the last payloads seen, for assertion in tests.
        self.last_create_payload: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def create_ticket(self, incident: dict[str, Any]) -> IncidentTicket:
        _require(incident, "incident_id")
        itype = incident.get("incident_type")
        severity = str(incident.get("severity", "medium"))
        labels = [label_for(itype), f"warrantor-incident/{incident['incident_id']}"]
        title = _build_title(incident)
        description = _build_description(incident)
        self._counter += 1
        ticket_id = f"{self.project_key}-{self._counter}"
        ticket = IncidentTicket(
            ticket_id=ticket_id,
            title=title,
            description=description,
            severity=severity,
            status="open",
            labels=labels,
            incident_id=str(incident["incident_id"]),
        )
        self.tickets[ticket_id] = ticket
        self.last_create_payload = {
            "incident": incident,
            "labels": labels,
            "priority": priority_for(itype, severity),
        }
        self.calls.append(
            ("create", {"incident_id": incident["incident_id"], "ticket_id": ticket_id})
        )
        return ticket

    def update_ticket(self, ticket_id: str, status: str) -> IncidentTicket:
        ticket = self._must_get(ticket_id)
        ticket.status = status
        self.calls.append(("update", {"ticket_id": ticket_id, "status": status}))
        return ticket

    def close_ticket(self, ticket_id: str, resolution: str) -> IncidentTicket:
        ticket = self._must_get(ticket_id)
        ticket.status = "closed"
        ticket.description = f"Resolved: {resolution}"
        self.calls.append(("close", {"ticket_id": ticket_id, "resolution": resolution}))
        return ticket

    def get(self, ticket_id: str) -> IncidentTicket | None:
        return self.tickets.get(ticket_id)

    def _must_get(self, ticket_id: str) -> IncidentTicket:
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise IncidentForwarderError(f"unknown ticket_id {ticket_id!r}")
        return ticket
