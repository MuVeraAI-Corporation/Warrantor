"""Tests for the AumOS Jira/Linear incident forwarder.

Uses the MockForwarder for the bulk of the tests (no network), plus a
monkeypatched JiraForwarder/LinearForwarder to verify payload shape and the
HTTP isolation points without touching the network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from aumos_jira import (
    DEFAULT_PROJECT_KEY,
    INCIDENT_LABELS,
    IncidentForwarderError,
    IncidentTicket,
    JiraForwarder,
    LinearForwarder,
    MockForwarder,
    label_for,
    priority_for,
)


def sample_incident(**overrides: Any) -> dict[str, Any]:
    base = {
        "incident_id": "inc-123",
        "incident_type": "goal_hijack",
        "severity": "critical",
        "summary": "agent diverted from declared goal",
        "details": "the coding agent began exfiltrating tokens",
        "agent_id": "spiffe://aumos.dev/agent/coding-1",
        "detected_at": 1_700_000_000.0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


def test_label_for_goal_hijack_is_security_critical():
    assert label_for("goal_hijack") == "security/critical"


def test_label_for_exfiltration_is_security_high():
    assert label_for("exfiltration") == "security/high"


def test_label_for_all_six_incident_types():
    # Every X9 incident type must have a label.
    for itype in (
        "goal_hijack",
        "exfiltration",
        "identity_compromise",
        "rogue_delegation",
        "tool_abuse",
        "memory_poisoning",
    ):
        assert label_for(itype).startswith("security/"), itype


def test_label_for_unknown_falls_back_to_low():
    assert label_for("totally_unknown") == "security/low"
    assert label_for(None) == "security/low"


def test_priority_for_uses_incident_type_then_severity():
    assert priority_for("goal_hijack") == "Highest"
    assert priority_for("exfiltration") == "High"
    # Unknown type but known severity.
    assert priority_for("unknown_type", severity="high") == "High"
    # Unknown type, no severity → default.
    assert priority_for("unknown_type") == "Medium"


# ---------------------------------------------------------------------------
# MockForwarder — create / update / close
# ---------------------------------------------------------------------------


def test_mock_create_ticket_basic():
    fwd = MockForwarder()
    ticket = fwd.create_ticket(sample_incident())
    assert isinstance(ticket, IncidentTicket)
    assert ticket.ticket_id == f"{DEFAULT_PROJECT_KEY}-1"
    assert ticket.status == "open"
    assert ticket.incident_id == "inc-123"
    assert "security/critical" in ticket.labels
    assert "aumos-incident/inc-123" in ticket.labels
    assert ticket.title == "agent diverted from declared goal"


def test_mock_create_ticket_uses_summary_when_missing():
    fwd = MockForwarder()
    inc = sample_incident()
    del inc["summary"]
    ticket = fwd.create_ticket(inc)
    # Falls back to a generated title.
    assert ticket.title.startswith("[AumOS] goal_hijack incident inc-123")


def test_mock_create_increments_ticket_id():
    fwd = MockForwarder()
    t1 = fwd.create_ticket(sample_incident(incident_id="a"))
    t2 = fwd.create_ticket(sample_incident(incident_id="b"))
    assert t1.ticket_id.endswith("-1")
    assert t2.ticket_id.endswith("-2")


def test_mock_create_requires_incident_id():
    fwd = MockForwarder()
    inc = sample_incident()
    del inc["incident_id"]
    with pytest.raises(IncidentForwarderError):
        fwd.create_ticket(inc)


def test_mock_update_ticket_changes_status():
    fwd = MockForwarder()
    t = fwd.create_ticket(sample_incident())
    updated = fwd.update_ticket(t.ticket_id, "in progress")
    assert updated.status == "in progress"
    # The stored ticket is mutated in place.
    assert fwd.get(t.ticket_id).status == "in progress"


def test_mock_close_ticket_sets_closed_and_resolution():
    fwd = MockForwarder()
    t = fwd.create_ticket(sample_incident())
    closed = fwd.close_ticket(t.ticket_id, "mitigated via kill-switch")
    assert closed.status == "closed"
    assert "mitigated via kill-switch" in closed.description


def test_mock_update_unknown_ticket_raises():
    fwd = MockForwarder()
    with pytest.raises(IncidentForwarderError):
        fwd.update_ticket("NOPE-99", "open")


def test_mock_records_call_audit_trail():
    fwd = MockForwarder()
    t = fwd.create_ticket(sample_incident())
    fwd.update_ticket(t.ticket_id, "in progress")
    fwd.close_ticket(t.ticket_id, "done")
    kinds = [c[0] for c in fwd.calls]
    assert kinds == ["create", "update", "close"]


def test_mock_maps_all_six_incident_types_to_labels():
    fwd = MockForwarder()
    for itype in INCIDENT_LABELS:
        t = fwd.create_ticket(sample_incident(incident_type=itype, incident_id=f"id-{itype}"))
        assert label_for(itype) in t.labels, itype


# ---------------------------------------------------------------------------
# JiraForwarder — payload shape + HTTP isolation (monkeypatched)
# ---------------------------------------------------------------------------


def test_jira_constructor_requires_webhook_or_base_and_token():
    with pytest.raises(IncidentForwarderError):
        JiraForwarder()
    with pytest.raises(IncidentForwarderError):
        JiraForwarder(base_url="https://x.atlassian.net")  # no token


def test_jira_create_payload_shape(monkeypatch):
    fwd = JiraForwarder(
        base_url="https://aumos.atlassian.net",
        api_token="tok",
        user_email="bot@aumos.dev",
        project_key="SEC",
    )
    captured: dict[str, Any] = {}

    def fake_post(self: JiraForwarder, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        captured["url"] = url
        captured["payload"] = payload
        return {"key": "SEC-42"}

    monkeypatch.setattr(JiraForwarder, "_post", fake_post)
    ticket = fwd.create_ticket(sample_incident())

    # The POST went to the REST create endpoint.
    assert captured["url"] == "https://aumos.atlassian.net/rest/api/3/issue"
    fields = captured["payload"]["fields"]
    assert fields["project"]["key"] == "SEC"
    assert fields["summary"] == "agent diverted from declared goal"
    assert fields["issuetype"]["name"] == "Incident"
    assert fields["priority"]["name"] == "Highest"  # goal_hijack → Highest
    assert "security/critical" in fields["labels"]
    # The returned ticket carries the Jira issue key + a browse URL.
    assert ticket.ticket_id == "SEC-42"
    assert ticket.url == "https://aumos.atlassian.net/browse/SEC-42"


def test_jira_webhook_path_uses_webhook_url(monkeypatch):
    fwd = JiraForwarder(webhook_url="https://hooks.example/jira")
    captured: dict[str, Any] = {}

    def fake_post(self: JiraForwarder, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        captured["url"] = url
        captured["payload"] = payload
        return {"key": "WH-1"}

    monkeypatch.setattr(JiraForwarder, "_post", fake_post)
    fwd.create_ticket(sample_incident())
    assert captured["url"] == "https://hooks.example/jira"


def test_jira_priority_from_severity_when_type_unknown(monkeypatch):
    fwd = JiraForwarder(base_url="https://x", api_token="t")
    captured: dict[str, Any] = {}

    def fake_post(self: JiraForwarder, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        captured["payload"] = payload
        return {"key": "X-1"}

    monkeypatch.setattr(JiraForwarder, "_post", fake_post)
    fwd.create_ticket(sample_incident(incident_type="brand_new_type", severity="high"))
    assert captured["payload"]["fields"]["priority"]["name"] == "High"


def test_jira_update_and_close_hit_transition_endpoint(monkeypatch):
    fwd = JiraForwarder(base_url="https://aumos.atlassian.net", api_token="t")
    urls: list[str] = []

    def fake_post(self: JiraForwarder, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        urls.append(url)
        return {}

    monkeypatch.setattr(JiraForwarder, "_post", fake_post)
    fwd.update_ticket("AUMOS-7", "in progress")
    fwd.close_ticket("AUMOS-7", "mitigated")
    assert urls == [
        "https://aumos.atlassian.net/rest/api/3/issue/AUMOS-7/transitions",
        "https://aumos.atlassian.net/rest/api/3/issue/AUMOS-7/transitions",
    ]


def test_jira_post_raises_typed_error_on_http_4xx():
    from urllib import error as urlerror

    fwd = JiraForwarder(base_url="https://x", api_token="t")

    # Replace urlopen in the module under test to raise an HTTPError.
    import aumos_jira as aj

    def raise_http(*a: Any, **k: Any) -> Any:
        raise urlerror.HTTPError(url="https://x", code=400, hdrs=None, fp=None, msg="bad")

    monkey_urlopen = raise_http
    # The module imports urlopen via `from urllib import request as urlrequest`.
    original = aj.urlrequest.urlopen
    aj.urlrequest.urlopen = monkey_urlopen  # type: ignore[assignment]
    try:
        with pytest.raises(IncidentForwarderError):
            fwd._post("https://x", {"x": 1})
    finally:
        aj.urlrequest.urlopen = original  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# LinearForwarder — payload shape + HTTP isolation
# ---------------------------------------------------------------------------


def test_linear_constructor_requires_token_and_team():
    with pytest.raises((IncidentForwarderError, TypeError)):
        LinearForwarder(api_token="t")  # no team_id
    with pytest.raises((IncidentForwarderError, TypeError)):
        LinearForwarder(team_id="t")  # no api_token


def test_linear_create_mutation_shape(monkeypatch):
    fwd = LinearForwarder(api_token="lin_tok", team_id="team-uuid")
    captured: dict[str, Any] = {}

    def fake_graphql(self: LinearForwarder, query: str) -> dict[str, Any]:
        captured["query"] = query
        return {"data": {"issueCreate": {"issue": {"id": "lin-1", "identifier": "ENG-9", "url": "https://linear.app/issue/ENG-9"}}}}

    monkeypatch.setattr(LinearForwarder, "_graphql", fake_graphql)
    ticket = fwd.create_ticket(sample_incident(severity="critical"))

    # The mutation must reference the team + priority derived from severity.
    assert "teamId: \"team-uuid\"" in captured["query"]
    assert "priority: 4" in captured["query"]  # critical → 4 (Urgent)
    assert "security/critical" in captured["query"]
    # Returned ticket carries Linear's id + url.
    assert ticket.ticket_id == "lin-1"
    assert ticket.url == "https://linear.app/issue/ENG-9"


def test_linear_priority_mapping():
    fwd = LinearForwarder(api_token="t", team_id="t")
    assert fwd._priority("critical") == 4
    assert fwd._priority("high") == 3
    assert fwd._priority("medium") == 2
    assert fwd._priority("low") == 1
    assert fwd._priority("unknown") == 2  # default


def test_linear_graphql_sends_auth_header(monkeypatch):
    fwd = LinearForwarder(api_token="lin_tok", team_id="team-uuid")
    captured: dict[str, Any] = {}

    class FakeResp:
        def __enter__(self) -> FakeResp:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"data": {"issueCreate": {"issue": {"id": "x"}}}}).encode()

    def fake_urlopen(req: Any, timeout: float | None = None) -> FakeResp:
        captured["headers"] = dict(req.headers)
        captured["url"] = req.full_url
        captured["data"] = json.loads(req.data.decode())
        return FakeResp()

    import aumos_jira as aj

    original = aj.urlrequest.urlopen
    aj.urlrequest.urlopen = fake_urlopen  # type: ignore[assignment]
    try:
        fwd._graphql("mutation { ping }")
    finally:
        aj.urlrequest.urlopen = original  # type: ignore[assignment]
    assert captured["url"] == "https://api.linear.app/graphql"
    # Authorization header is the bare Linear API key.
    assert captured["headers"]["Authorization"] == "lin_tok"


# ---------------------------------------------------------------------------
# Cross-forwarder interface equivalence
# ---------------------------------------------------------------------------


def test_all_forwarders_share_incident_ticket_type():
    """All three forwarders return IncidentTicket from create/update/close."""
    fwd = MockForwarder()
    t = fwd.create_ticket(sample_incident())
    assert isinstance(t, IncidentTicket)
    assert isinstance(fwd.update_ticket(t.ticket_id, "open"), IncidentTicket)
    assert isinstance(fwd.close_ticket(t.ticket_id, "done"), IncidentTicket)
