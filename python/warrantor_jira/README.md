# warrantor-jira

Auto-create Jira or Linear tickets from AumOS agent incidents (P9 / X9).

Consumes the normalised incident dict produced by `incident_exchange` and maps
each AumOS incident type to a ticket label and priority.

## Forwarders

| Class             | Target          | Auth                                          |
| ----------------- | --------------- | --------------------------------------------- |
| `JiraForwarder`   | Jira Cloud      | REST: `base_url`+`api_token`+`user_email`, or incoming `webhook_url` |
| `LinearForwarder` | Linear GraphQL  | `api_token` + `team_id`                       |
| `MockForwarder`   | in-memory       | none — for tests and dry-runs                 |

All three implement the same interface:

```python
ticket = fwd.create_ticket(incident_dict)      # -> IncidentTicket
fwd.update_ticket(ticket.ticket_id, "in progress")
fwd.close_ticket(ticket.ticket_id, "mitigated")
```

## Incident-type mapping (per AumOS X9)

| incident_type         | label                  | Jira priority | Linear priority |
| --------------------- | ---------------------- | ------------- | --------------- |
| `goal_hijack`         | `security/critical`    | Highest       | 4 (Urgent)      |
| `exfiltration`        | `security/high`        | High          | 3 (High)        |
| `identity_compromise` | `security/high`        | High          | 3 (High)        |
| `rogue_delegation`    | `security/medium`      | Medium        | 2 (Medium)      |
| `tool_abuse`          | `security/medium`      | Medium        | 2 (Medium)      |
| `memory_poisoning`    | `security/medium`      | Medium        | 2 (Medium)      |
| `<unknown>`           | `security/low`         | (from severity)| (from severity)|

Every ticket is tagged with `warrantor-incident/<incident_id>` so the originating
AumOS incident is always traceable from the ticket.

## Usage

```python
from warrantor_jira import JiraForwarder, MockForwarder

# Production
fwd = JiraForwarder(
    base_url="https://yourorg.atlassian.net",
    api_token=os.environ["JIRA_API_TOKEN"],
    user_email="bot@aumos.dev",
    project_key="SEC",
)
ticket = fwd.create_ticket(incident_dict)

# Tests / dry-run
fwd = MockForwarder()
ticket = fwd.create_ticket(incident_dict)
```

## Design notes

- **Zero third-party deps.** HTTP is done with stdlib `urllib`; the call is
  isolated in `_post` (Jira) / `_graphql` (Linear) so tests monkeypatch it
  rather than hitting the network.
- **Fail-loud.** Network errors are wrapped in `IncidentForwarderError` so the
  caller's incident pipeline can retry or fall back (e.g. to the kill-switch).
- **Traceability.** Every ticket carries the `incident_id` as both a label and
  a custom field, so a JQL/Linear search can map tickets back to AumOS
  incidents.

## Running the tests

```bash
pip install -e '.[dev]'
pytest
```
