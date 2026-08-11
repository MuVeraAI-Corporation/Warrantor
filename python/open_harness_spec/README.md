# warrantor-open-harness-spec (X3)

A vendor-neutral specification for agent harnesses. Defines five mandatory interfaces
as Python ``Protocol`` classes:

- **AgentIdentity** — agent identity surface (who is running).
- **ToolPermission** — tool-call authorization surface (may the agent call this tool).
- **AuditEvent** — structured audit surface (what happened).
- **AttestationEnvelope** — hardware attestation surface (was the harness trustworthy).
- **EvaluationReport** — evaluation surface (did the agent meet the bar).

Plus a :class:`ConformanceChecker` that verifies a candidate harness implements all
five interfaces and exposes the mandatory attributes.

See `docs/rfcs/X3-open-harness-spec.md`.
