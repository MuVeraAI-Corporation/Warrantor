# aumos-red-team-cloud (A7)

Continuous adversarial simulation service. Wraps A2 `adversaria`'s
`AttackSuite` into a scheduled job runner that fires attack suites on a
configurable cadence and aggregates results per target.

Components:
- **ScenarioLibrary** — registry of named attack scenarios (suites +
  targets).
- **ScheduleConfig** — period + jitter for each scenario.
- **JobRunner** — runs scheduled scenarios and records results.
- **ResultAggregator** — rolls up per-scenario, per-attack-type success
  rates into trend lines.

See `docs/rfcs/A7-red-team-cloud.md`.
