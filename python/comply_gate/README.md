# aumos-comply-gate (A4)

CI/CD compliance gates for AumOS components. Parses a `.complygate.yml`
config and enforces four gate types:

- **test-coverage** — minimum line coverage threshold (default 80%).
- **sbom-present** — requires a Software Bill of Materials to exist.
- **eval-passed** — requires the latest eval run to pass.
- **disclosure-filed** — requires a vulnerability disclosure to be filed.

Plus **break-glass** overrides: a gate failure can be overridden, but only
with **two mandatory approvers** (no single-approver bypasses).

See `docs/rfcs/A4-comply-gate.md`.
