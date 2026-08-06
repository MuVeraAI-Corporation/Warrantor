"""AumOS incident-exchange (X9) — normalized agent incidents.

Six incident types, an OCSF extension mapping, a MITRE ATLAS technique
mapping per incident type, and an :class:`IncidentRegistry` for dedup,
severity ordering, and exchange.

Incident types:
    goal_hijack          — agent was diverted from its declared goal.
    memory_poisoning     — agent's memory store was tampered.
    tool_abuse           — agent misused a tool (privilege escalation, recursion, ...).
    identity_compromise  — agent identity was spoofed or stolen.
    exfiltration         — sensitive data was sent out of the trust boundary.
    rogue_delegation     — agent delegated to an unauthorized sub-agent.

See ``docs/rfcs/X9-incident-exchange.md``.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Enums + constants
# ---------------------------------------------------------------------------
class IncidentType(str, Enum):
    """The six normalized agent-incident types."""

    GOAL_HIJACK = "goal_hijack"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_ABUSE = "tool_abuse"
    IDENTITY_COMPROMISE = "identity_compromise"
    EXFILTRATION = "exfiltration"
    ROGUE_DELEGATION = "rogue_delegation"


class Severity(str, Enum):
    """Incident severity, ordered low..critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


# MITRE ATLAS technique mapping per incident type.
# Reference: https://atlas.mitre.org/techniques
ATLAS_MAPPING: dict[IncidentType, list[str]] = {
    IncidentType.GOAL_HIJACK: ["AML.T0051", "AML.T0050"],
    IncidentType.MEMORY_POISONING: ["AML.T0020", "AML.T0019"],
    IncidentType.TOOL_ABUSE: ["AML.T0048", "AML.T0051"],
    IncidentType.IDENTITY_COMPROMISE: ["AML.T0051", "AML.T0043"],
    IncidentType.EXFILTRATION: ["AML.T0037", "AML.T0019"],
    IncidentType.ROGUE_DELEGATION: ["AML.T0048", "AML.T0051"],
}


# OCSF extension class ids. OCSF uses a numeric class id + category_uid; we
# extend the "Security Finding" class (2004) and "Incident" class (3003) with
# an aumos-specific activity_id for agent incidents.
OCSF_CLASS_UID = 3003  # Incident class per OCSF v1.1
OCSF_CATEGORY_UID = 3  # Application Security
OCSF_ACTIVITY_UID: dict[IncidentType, int] = {
    IncidentType.GOAL_HIJACK: 1,
    IncidentType.MEMORY_POISONING: 2,
    IncidentType.TOOL_ABUSE: 3,
    IncidentType.IDENTITY_COMPROMISE: 4,
    IncidentType.EXFILTRATION: 5,
    IncidentType.ROGUE_DELEGATION: 6,
}


# ---------------------------------------------------------------------------
# Incident dataclass
# ---------------------------------------------------------------------------
@dataclass
class Incident:
    """One normalized agent incident.

    ``fingerprint`` is a content-derived stable hash used by the registry to
    dedup near-identical incidents.
    """

    incident_type: IncidentType
    severity: Severity
    agent_id: str
    summary: str
    occurred_at: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    incident_id: str = ""

    def __post_init__(self) -> None:
        if not self.occurred_at:
            self.occurred_at = datetime.now(timezone.utc).isoformat()
        if not self.incident_id:
            self.incident_id = str(uuid.uuid4())

    def fingerprint(self) -> str:
        """Return a stable content hash used for dedup."""
        h = hashlib.sha256()
        h.update(self.incident_type.value.encode("utf-8"))
        h.update(b"|")
        h.update(self.agent_id.encode("utf-8"))
        h.update(b"|")
        h.update(self.summary.strip().lower().encode("utf-8"))
        return h.hexdigest()

    def atlas_techniques(self) -> list[str]:
        """Return the MITRE ATLAS technique ids mapped to this incident type."""
        return list(ATLAS_MAPPING.get(self.incident_type, []))

    def to_ocsf(self) -> dict[str, Any]:
        """Translate the incident into an OCSF v1.1 ``Incident`` event dict."""
        return {
            "class_uid": OCSF_CLASS_UID,
            "category_uid": OCSF_CATEGORY_UID,
            "activity_id": OCSF_ACTIVITY_UID[self.incident_type],
            "severity_id": _SEVERITY_RANK[self.severity],
            "type_uid": OCSF_CLASS_UID * 100 + OCSF_ACTIVITY_UID[self.incident_type],
            "incident_id": self.incident_id,
            "title": f"{self.incident_type.value} on {self.agent_id}",
            "summary": self.summary,
            "severity": self.severity.value,
            "time": self.occurred_at,
            "actor": {"name": self.agent_id, "type": "agent"},
            "metadata": {
                "source": "aumos",
                "atlas_techniques": self.atlas_techniques(),
                "evidence": list(self.evidence),
                "extras": dict(self.metadata),
            },
        }

    def to_dict(self) -> dict[str, Any]:
        """Plain (non-OCSF) serialization."""
        return {
            "incident_id": self.incident_id,
            "incident_type": self.incident_type.value,
            "severity": self.severity.value,
            "agent_id": self.agent_id,
            "summary": self.summary,
            "occurred_at": self.occurred_at,
            "evidence": list(self.evidence),
            "metadata": dict(self.metadata),
            "atlas_techniques": self.atlas_techniques(),
            "fingerprint": self.fingerprint(),
        }


# ---------------------------------------------------------------------------
# IncidentRegistry
# ---------------------------------------------------------------------------
@dataclass
class RegistryStats:
    """Aggregated statistics over a registry's incidents."""

    total: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the stats to a plain dict."""
        return {
            "total": self.total,
            "by_type": dict(self.by_type),
            "by_severity": dict(self.by_severity),
        }


class IncidentRegistry:
    """Holds incidents, dedups by fingerprint, and supports exchange queries.

    The registry dedups incidents that have the same fingerprint (incident
    type + agent + normalized summary) — the canonical near-duplicate signal.
    Queries support filtering by type, severity, and time window, plus an
    OCSF export.
    """

    def __init__(self) -> None:
        self._by_fp: dict[str, Incident] = {}
        self._by_id: dict[str, Incident] = {}
        self._order: list[str] = []  # ordered list of incident_ids

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self) -> Iterable[Incident]:
        return (self._by_id[i] for i in self._order)

    def add(self, incident: Incident) -> Incident:
        """Add ``incident``; returns the canonical (deduped) incident.

        If a fingerprint-equal incident is already present, the higher-severity
        of the two wins and is returned; the loser is dropped. Ties keep the
        existing entry.
        """
        fp = incident.fingerprint()
        if fp in self._by_fp:
            existing = self._by_fp[fp]
            if _SEVERITY_RANK[incident.severity] > _SEVERITY_RANK[existing.severity]:
                # replace
                self._remove(existing)
                self._store(incident)
                return incident
            return existing
        self._store(incident)
        return incident

    def _store(self, incident: Incident) -> None:
        self._by_fp[incident.fingerprint()] = incident
        self._by_id[incident.incident_id] = incident
        self._order.append(incident.incident_id)

    def _remove(self, incident: Incident) -> None:
        self._by_fp.pop(incident.fingerprint(), None)
        self._by_id.pop(incident.incident_id, None)
        if incident.incident_id in self._order:
            self._order.remove(incident.incident_id)

    def get(self, incident_id: str) -> Incident | None:
        """Look up an incident by id."""
        return self._by_id.get(incident_id)

    def filter(
        self,
        *,
        incident_type: IncidentType | None = None,
        min_severity: Severity | None = None,
    ) -> list[Incident]:
        """Return incidents matching the filters, sorted by severity (desc)."""
        out: list[Incident] = []
        min_rank = _SEVERITY_RANK[min_severity] if min_severity else 0
        for inc in self:
            if incident_type is not None and inc.incident_type != incident_type:
                continue
            if _SEVERITY_RANK[inc.severity] < min_rank:
                continue
            out.append(inc)
        out.sort(key=lambda i: (-_SEVERITY_RANK[i.severity], i.occurred_at))
        return out

    def stats(self) -> RegistryStats:
        """Return aggregate statistics."""
        s = RegistryStats(total=len(self))
        for inc in self:
            t = inc.incident_type.value
            sev = inc.severity.value
            s.by_type[t] = s.by_type.get(t, 0) + 1
            s.by_severity[sev] = s.by_severity.get(sev, 0) + 1
        return s

    def export_ocsf(self) -> list[dict[str, Any]]:
        """Export every incident as an OCSF ``Incident`` event."""
        return [inc.to_ocsf() for inc in self]


__all__ = [
    "ATLAS_MAPPING",
    "Incident",
    "IncidentRegistry",
    "IncidentType",
    "OCSF_ACTIVITY_UID",
    "OCSF_CATEGORY_UID",
    "OCSF_CLASS_UID",
    "RegistryStats",
    "Severity",
]
