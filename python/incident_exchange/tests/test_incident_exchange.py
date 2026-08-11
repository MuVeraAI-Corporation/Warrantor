"""Tests for incident-exchange: types, ATLAS/OCSF mapping, registry."""

from __future__ import annotations

from incident_exchange import (
    ATLAS_MAPPING,
    OCSF_ACTIVITY_UID,
    OCSF_CLASS_UID,
    Incident,
    IncidentRegistry,
    IncidentType,
    Severity,
)


def make_incident(
    incident_type: IncidentType = IncidentType.EXFILTRATION,
    severity: Severity = Severity.HIGH,
    agent_id: str = "agent-1",
    summary: str = "exfil observed",
) -> Incident:
    return Incident(
        incident_type=incident_type,
        severity=severity,
        agent_id=agent_id,
        summary=summary,
    )


# ---------- Incident ----------
def test_incident_has_id_and_timestamp() -> None:
    inc = make_incident()
    assert inc.incident_id
    assert inc.occurred_at


def test_fingerprint_is_stable_for_same_content() -> None:
    a = make_incident(summary="Exfil Observed")  # case differs
    b = make_incident(summary="exfil observed")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_differs_for_different_agents() -> None:
    a = make_incident(agent_id="a1")
    b = make_incident(agent_id="a2")
    assert a.fingerprint() != b.fingerprint()


def test_atlas_mapping_covers_every_type() -> None:
    for t in IncidentType:
        assert t in ATLAS_MAPPING
        assert len(ATLAS_MAPPING[t]) >= 1
        assert all(tid.startswith("AML.T") for tid in ATLAS_MAPPING[t])


def test_incident_atlas_techniques_match_mapping() -> None:
    inc = make_incident(incident_type=IncidentType.GOAL_HIJACK)
    assert inc.atlas_techniques() == ATLAS_MAPPING[IncidentType.GOAL_HIJACK]


# ---------- OCSF translation ----------
def test_to_ocsf_emits_required_fields() -> None:
    inc = make_incident(severity=Severity.CRITICAL)
    ocsf = inc.to_ocsf()
    assert ocsf["class_uid"] == OCSF_CLASS_UID
    assert ocsf["severity_id"] == 4  # critical
    assert ocsf["activity_id"] == OCSF_ACTIVITY_UID[IncidentType.EXFILTRATION]
    assert ocsf["type_uid"] == OCSF_CLASS_UID * 100 + ocsf["activity_id"]
    assert ocsf["actor"]["name"] == "agent-1"
    assert "AML.T0037" in ocsf["metadata"]["atlas_techniques"]


def test_to_dict_round_trips() -> None:
    inc = make_incident()
    d = inc.to_dict()
    assert d["incident_type"] == "exfiltration"
    assert d["severity"] == "high"
    assert d["fingerprint"] == inc.fingerprint()


# ---------- Registry ----------
def test_registry_dedups_on_fingerprint() -> None:
    reg = IncidentRegistry()
    a = reg.add(make_incident(summary="dup"))
    b = reg.add(make_incident(summary="DUP"))  # same fingerprint
    assert len(reg) == 1
    assert a.incident_id == b.incident_id


def test_registry_replaces_with_higher_severity() -> None:
    reg = IncidentRegistry()
    low = reg.add(make_incident(severity=Severity.LOW, summary="x"))
    high = reg.add(make_incident(severity=Severity.CRITICAL, summary="x"))
    assert len(reg) == 1
    canonical = next(iter(reg))
    assert canonical.incident_id == high.incident_id
    assert canonical.severity == Severity.CRITICAL
    assert canonical.incident_id != low.incident_id


def test_registry_keeps_existing_on_severity_tie_or_lower() -> None:
    reg = IncidentRegistry()
    first = reg.add(make_incident(severity=Severity.HIGH, summary="x"))
    reg.add(make_incident(severity=Severity.LOW, summary="x"))
    assert len(reg) == 1
    assert next(iter(reg)).incident_id == first.incident_id


def test_registry_filter_by_type_and_min_severity() -> None:
    reg = IncidentRegistry()
    reg.add(make_incident(IncidentType.EXFILTRATION, Severity.CRITICAL, summary="a"))
    reg.add(make_incident(IncidentType.TOOL_ABUSE, Severity.LOW, summary="b"))
    reg.add(make_incident(IncidentType.EXFILTRATION, Severity.MEDIUM, summary="c"))
    exfil = reg.filter(incident_type=IncidentType.EXFILTRATION)
    assert len(exfil) == 2
    assert exfil[0].severity == Severity.CRITICAL  # sorted desc
    high_only = reg.filter(min_severity=Severity.HIGH)
    assert len(high_only) == 1
    assert high_only[0].severity == Severity.CRITICAL


def test_registry_stats_aggregate() -> None:
    reg = IncidentRegistry()
    reg.add(make_incident(IncidentType.EXFILTRATION, Severity.HIGH, summary="a"))
    reg.add(make_incident(IncidentType.TOOL_ABUSE, Severity.LOW, summary="b"))
    stats = reg.stats()
    d = stats.to_dict()
    assert d["total"] == 2
    assert d["by_type"]["exfiltration"] == 1
    assert d["by_severity"]["high"] == 1


def test_registry_export_ocsf() -> None:
    reg = IncidentRegistry()
    reg.add(make_incident(summary="x"))
    ocsf = reg.export_ocsf()
    assert len(ocsf) == 1
    assert ocsf[0]["class_uid"] == OCSF_CLASS_UID


def test_registry_get_by_id() -> None:
    reg = IncidentRegistry()
    inc = reg.add(make_incident(summary="x"))
    assert reg.get(inc.incident_id) is inc
    assert reg.get("missing") is None
