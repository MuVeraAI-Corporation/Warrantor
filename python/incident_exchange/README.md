# warrantor-incident-exchange (X9)

Normalized agent-incident exchange. Six incident types:

- `goal_hijack` — agent was diverted from its declared goal.
- `memory_poisoning` — agent's memory store was tampered.
- `tool_abuse` — agent misused a tool (privilege escalation, recursion, ...).
- `identity_compromise` — agent identity was spoofed or stolen.
- `exfiltration` — sensitive data was sent out of the trust boundary.
- `rogue_delegation` — agent delegated to an unauthorized sub-agent.

Features:
- OCSF (Open Cybersecurity Schema Framework) extension mapping.
- MITRE ATLAS technique mapping per incident type.
- :class:`IncidentRegistry` for dedup, severity ordering, and exchange.

See `docs/rfcs/X9-incident-exchange.md`.
